from __future__ import print_function
from ConfigParser import SafeConfigParser
import os
import threading
import re
import string

#General utility objects used by both auditor and auditee.

config = SafeConfigParser()

config_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),'tlsnotary.ini')

required_options = {'IRC':['irc_server','irc_port','channel_name'],'General':['msg_chunk_size','dark']}

def load_program_config():    
    loadedFiles = config.read([config_location])
    #detailed sanity checking :
    #did the file exist?
    if len(loadedFiles) != 1:
        raise Exception("Could not find config file: "+config_location)
    #check for sections
    for s in required_options:
        if s not in config.sections():
            raise Exception("Config file does not contain the required section: "+s)
    #then check for specific options
    for k,v in required_options.iteritems():
        for o in v:
            if o not in config.options(k):
                raise Exception("Config file does not contain the required option: "+o)


#a thread which returns a value. This is achieved by passing self as the first argument to a target function
#the target_function(parentthread, arg1, arg2) can then set, e.g parentthread.retval
class ThreadWithRetval(threading.Thread):
    def __init__(self, target, args=()):
        super(ThreadWithRetval, self).__init__(target=target, args = (self,)+args )
    retval = ''

def bigint_to_bytearray(bigint):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    return bytearray(m_bytes)


class SSLClientSession(object):
    def __init__(self):
        print ("initialising SSLSession")
        tlsVersionNum = '1.0'
        nAuditeeEntropy = 11
        nAuditorEntropy = 8
        auditorSecret = None
        auditeeSecret = None
        encFirstHalfPMS = None
        encSecondHalfPMS = None
        encPMS = None
        #client hello, server hello, certificate, server hello done, client key exchange, change cipher spec, finished
        self.handshakeMessages = [None * 7]
        #client random can be created immediately on instantiation
        cr_time = shared.bigint_to_bytearray(int(time.time()))
        clientRandom = cr_time + os.urandom(28)
        serverRandom = None
        cipherSuites = {47:['AES128',20,20,16,16,16,16],53:['AES256',20,20,32,32,16,16],\
                        4:['RC4MD5',20,20,16,16,0,0],5:['RC4SHA',16,16,16,16,0,0]}
        chosenCipherSuite = None
        pAuditor = None
        pAuditee = None
        masterSecretHalfAuditor = None
        masterSecretHalfAuditee = None
        pMasterSecretAuditor = None
        pMasterSecretAuditee = None
        serverMacKey = None
        clientMacKey = None
        serverEncKey = None
        clientEncKey = None
        serverIV = None
        client IV = None
        serverCertificate = None
        serverPubKey = None
        serverExponent = 65537

    def setMasterSecretHalf(self,half=1,providedPValue):
        if not len(providedPValue)==24: return None
        if half == 1:
            self.masterSecretHalfAuditee = shared.xor(pAuditee[:24],providedPValue)
            return self.masterSecretHalfAuditee
        elif half == 2:
            self.masterSecretHalfAuditor = shared.xor(pAuditor[24:],providedPValue)
            return self.masterSecretHalfAuditor
        else:
            return None

    def setCipherSuite(self, csByte):
        csInt = shared.ba2int(csByte)
        if csInt not in cipherSuites.keys(): return None
        chosenCipherSuite = csInt
        return csInt

    def processServerHello(self,sh_cert_shd):
        #server hello always starts with 16 03 01 * * 02
        #certificate always starts with 16 03 01 * * 0b
        shd = '\x16\x03\x01\x00\x04\x0e\x00\x00\x00'
        sh_magic = re.compile(b'\x16\x03\x01..\x02')
        if not re.match(sh_magic, sh_cert_shd): raise Exception ('Invalid server hello')
        if not sh_cert_shd.endswith(shd): raise Exception ('invalid server hello done')
        #find the beginning of certificate message
        cert_magic = re.compile(b'\x16\x03\x01..\x0b')
        cert_match = re.search(cert_magic, sh_cert_shd)
        if not cert_match: raise Exception ('Invalid certificate message')
        cert_start_position = cert_match.start()
        sh = sh_cert_shd[:cert_start_position]
        self.serverCertificate = sh_cert_shd[cert_start_position : -len(shd)]
        self.serverRandom = sh[11:43]
        return (self.serverCertificate,self.serverRandom)

    def getEncryptedPMS(self):
        if not (self.encFirstHalfPMS and self.encSecondHalfPMS and self.serverPubKey): return None
        self.encPMS =  self.encFirstHalfPMS * self.encSecondHalfPMS % self.serverPubKey
        return self.encPMS

    def setAuditeeSecret(self,secret):
        '''Sets up the auditee's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.
        secret should be a bytearray of length nAuditeeEntropy'''
        if len(secret) != self.nAuditeeEntropy: return None
        if not (self.clientRandom and self.serverRandom): return None

        self.auditeeSecret = secret
        label = 'master secret'
        seed = self.clientRandom + self.serverRandom
        self.pAuditee = TLS10PRF(label+seed,first_half = self.auditeeSecret)[0]

        #we can construct the encrypted form if pubkey is known
        if (serverPubKey):
            pms1 = '\x03\x01'+self.auditeeSecret + ('\x00' * (24-2-self.nAuditeeSecret))
            encFirstHalfPMS = pow( shared.ba2int('\x02'+('\x01'*63)+os.urandom(15)+'\x00'+\
            pms1+('\x00'*24)) + 1, self.serverExponent, self.serverPubKey)

        #can construct the full encrypted pre master secret if
        #the auditor's half is already calculated
        if (self.encSecondHalfPMS):
            self.getEncryptedPMS()

        return (self.pAuditee,self.encPMS)

    def setAuditorSecret(self,secret):
        '''Sets up the auditor's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.
        'secret' should be a bytearray of length nAuditorEntropy'''
        if len(secret) != self.nAuditorEntropy: return None
        if not (self.clientRandom and self.serverRandom): return None

        self.auditorSecret = secret
        label = 'master secret'
        seed = self.clientRandom + self.serverRandom
        self.pAuditor = TLS10PRF(label+seed,second_half = self.auditorSecret)[1]

        #we can construct the encrypted form if pubkey is known
        if (serverPubKey):
            pms2 =  self.auditorSecret + ('\x00' * (24-self.nAuditorEntropy-1)) + '\x01'
            encSecondHalfPMS = pow( int(('\x01'+('\x01'*63)+os.urandom(15)+ \
            ('\x00'*25)+pms2).encode('hex'),16), serverExponent, serverPubKey )

        return (self.pAuditor,self.encSecondHalfPMS)

    def setClientKeyExchange(self):
        if not self.encPMS: return None
        self.handshakeMessages[4] = '\x16\x03\x01\x01\x06\x10\x00\x01\x02\x01\00' + self.encPMS
        return self.handshakeMessages[4]

    def extractModAndExp(self, derEncodedKey):
        #extract n and e from the pubkey
        try:
            rv  = decoder.decode(derEncodedKey, asn1Spec=univ.Sequence())
            bitstring = rv[0].getComponentByPosition(1)
            #bitstring is a list of ints, like [01110001010101000...]
            #convert it into into a string   '01110001010101000...'
            stringOfBits = ''
            for bit in bitstring:
                bit_as_str = str(bit)
                stringOfBits += bit_as_str
            #treat every 8 chars as an int and pack the ints into a bytearray
            ba = bytearray()
            for i in range(0, len(stringOfBits)/8):
                onebyte = stringOfBits[i*8 : (i+1)*8]
                oneint = int(onebyte, base=2)
                ba.append(oneint)
            #decoding the nested sequence
            rv  = decoder.decode(str(ba), asn1Spec=univ.Sequence())
            exponent = rv[0].getComponentByPosition(1)
            modulus = rv[0].getComponentByPosition(0)
            self.serverPubKey = int(modulus)
            self.serverExponent = int(exponent)
        except: return None
        return (self.serverPubKey,self.serverExponent)

        ''' what is this?
        modulus_len_int = len(n)
        modulus_len = shared.bigint_to_bytearray(modulus_len_int)
        if len(modulus_len) == 1: modulus_len.insert(0,0)  #zero-pad to 2 bytes
        '''

    def doKeyExpansion(self):
        '''A note about partial expansions:
        Often we will have sufficient information to extract particular
        keys, e.g. the client keys, but not others, e.g. the server keys.
        This should be handled by passing in garbage to fill out the relevant
        portions of the two master secret halves. TODO find a way to make this
        explicit so that querying the object will only give real keys.'''
        label = 'key expansion'
        seed = self.serverRandom + self.clientRandom
        #for maximum flexibility, we will compute the sha1 or hmac
        #or the full keys, based on what secrets currently exist in this object
        if self.masterSecretHalfAuditee:
            self.pMasterSecretAuditee = shared.TLS10PRF(label+seed,req_bytes=140,second_half=self.masterSecretHalfAuditee)[1]
        if self.masterSecretHalfAuditor:
            self.pMasterSecretAuditor = shared.TLS10PRF(label+seed,req_bytes=140,first_half=self.masterSecretHalfAuditor)[0]

        if self.pMasterSecretAuditee and self.pMasterSecretAuditor:
            keyExpansion = shared.TLS10PRF(label+seed,req_bytes=140,full_secret=self.masterSecretHalfAuditee+self.masterSecretHalfAuditor)[2]
            #we have the raw key expansion, but want the keys. Use the data
            #embedded in the cipherSuite dict to identify the boundaries.
            if not self.chosenCipherSuite:
                print ("Cannot expand ssl keys without a chosen cipher suite.")
                return None

            keyAccumulator = []
            ctr=0
            for i in range(6):
                keySize = self.cipherSuites[self.chosenCipherSuite][i+1]
                keyAccumulator.append(keyExpansion[ctr:ctr+keySize)
                ctr += keySize

            self.clientMacKey,self.serverMacKey,self.clientEncKey,self.serverEncKey,self.clientIV,self.serverIV = keyAccumulator
            return keyAccumulator

    #currently this is only of use if the entire
    #master secret is known locally.
    def getVerifyDataForFinished(self):
        if self.handshakeMessages[:6] != filter(None,self.handshakeMessages[:6]): return None
        handshakeData = ''.join([x[5:] for x in self.handshakeMessages[:6]])
        sha_verify = hashlib.sha1(handshakeData).digest()
        md5_verify = hashlib.md5(handshakeData).digest()
        label = 'client finished'
        seed = md5_verify + sha_verify
        ms = self.masterSecretHalfAuditee+self.masterSecretHalfAuditor
        #we don't store the verify data locally, just return it
        return shared.TLS10PRF(label+seed,req_bytes=12,full_secret=ms)[2]

    #TODO currently only applies to a AES-CBC 256 handshake
    def getCKECCSF(self):
    '''sets the handshake messages change cipher spec and finished,
    and returns the three final handshake messages client key exchange,
    change cipher spec and finished. '''
        #send and expect change cipher spec from google.com as a sign of success
        self.handshakeMessages[5] = '\x14\x03\01\x00\x01\x01'
        verifyData = self.getVerifyDataForFinished()
        if not verifyData: return None
        #HMAC and AES-encrypt the verify_data
        hmacVerify = hmac.new(self.clientMacKey, '\x00\x00\x00\x00\x00\x00\x00\x00' \
        + '\x16' + '\x03\x01' + '\x00\x10' + '\x14\x00\x00\x0c' + verifyData, sha1).digest()
        moo = AESModeOfOperation()
        cleartext = '\x14\x00\x00\x0c' + verifyData + hmacVerify
        cleartextList = shared.bigint_to_list(shared.ba2int(cleartext))
        clientEncList =  shared.bigint_to_list(shared.ba2int(self.clientEncKey))
        clientIVList =  shared.bigint_to_list(shared.ba2int(self.clientIV))
        paddedCleartext = cleartext + ('\x0b' * 12) #this is TLS CBC padding, NOT PKCS7
        try:
            mode, origLen, hmacedVerifyData = \
            moo.encrypt( str(paddedCleartext), moo.modeOfOperation['CBC'], \
            clientEncList, moo.aes.keySize['SIZE_256'], clientIVList)
        except Exception, e:
            print ('Caught exception while doing slowaes encrypt: ', e)
            raise
        self.handshakeMessages[6] = '\x16\x03\x01\x00\x30' + bytearray(hmacedVerifyData)
        return ''.join(self.handshakeMessages[4:6])

def xor(a,b):
    return bytearray([ord(a) ^ ord(b) for a,b in zip(a,b)])

def bigint_to_list(bigint):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    return m_bytes

#convert bytearray into int
def ba2int(byte_array):
    return int(str(byte_array).encode('hex'), 16)

def get_ciphertext_from_asciidump(ascii_dump):
    '''Explanation
    Relies on tshark's -x hex/ascii dump output format as of 1.10.7
    Given tshark -x output ascii_dump, return the complete ciphertext
    extraced from the reassembled TCP segments, with ssl record headers stripped.
    The returned ciphertext is formatted as a list of integers, suitable for input into
    AES decryption.
    NB the input tshark -x dump should *not* be generated with an sslkeylogfile (I am
    not sure that it wouldn't work, but it's not intended).
    This ciphertext generation is intended to be carried by an auditee who does *not*
    have access to the master secrets.
    '''

    #sanity checks
    if not ascii_dump:
        raise Exception("Cannot find ciphertext; tshark ascii dump appears to be empty.")

    ciphertext = ''

    for data_chunk in re.split('Reassembled TCP \([0-9]+ bytes\):',ascii_dump)[1:]:
        rtcp_ciphertext = ''
        remaining = filter(None,data_chunk.split('\n'))
        #TODO make this easier on the eye.
        linenums = [i for i,x in enumerate(remaining) if (not all(c in string.hexdigits for c in x[:4])) or ('0000'==x[:4] and i != 0)]
        cipher_lines = remaining[:min(linenums)] if len(linenums) else remaining
        for cipher_line in cipher_lines:
            try:
                rtcp_ciphertext += cipher_line.split('  ')[1].replace(' ','').decode('hex')
            except:
                print ("Failed to extract ciphertext from this line: ",cipher_line)
                raise
        #remove the ssl record header (170301XXXX)
        ciphertext += rtcp_ciphertext[5:]
    if not ciphertext:
        raise Exception("Could not find ciphertext in hex-ascii dump")

    ciphertext = map(ord,ciphertext)
    return ciphertext

#look at tshark's ascii dump (option '-x') to better understand the parsing taking place
def get_html_from_asciidump(ascii_dump):
    hexdigits = set('0123456789abcdefABCDEF')
    binary_html = bytearray()

    if ascii_dump == '':
        print ('empty frame dump',end='\r\n')
        return -1

    #We are interested in
    # "Uncompressed entity body" for compressed HTML (both chunked and not chunked). If not present, then
    # "De-chunked entity body" for no-compression, chunked HTML. If not present, then
    # "Reassembled SSL" for no-compression no-chunks HTML in multiple SSL segments, If not present, then
    # "Decrypted SSL data" for no-compression no-chunks HTML in a single SSL segment.

    uncompr_pos = ascii_dump.rfind('Uncompressed entity body')
    if uncompr_pos != -1:
        for line in ascii_dump[uncompr_pos:].split('\n')[1:]:
            #convert ascii representation of hex into binary so long as first 4 chars are hexdigits
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #if first 4 chars are not hexdigits, we reached the end of the section
                break
        return binary_html

    #else
    dechunked_pos = ascii_dump.rfind('De-chunked entity body')
    if dechunked_pos != -1:
        for line in ascii_dump[dechunked_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                break
        return binary_html

    #else
    reassembled_pos = ascii_dump.rfind('Reassembled SSL')
    if reassembled_pos != -1:
        for line in ascii_dump[reassembled_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #http HEADER is delimited from HTTP body with '\r\n\r\n'
                if binary_html.find('\r\n\r\n') == -1:
                    return -1
                break
        return binary_html.split('\r\n\r\n', 1)[1]

    #else
    decrypted_pos = ascii_dump.rfind('Decrypted SSL data')
    if decrypted_pos != -1:
        for line in ascii_dump[decrypted_pos:].split('\n')[1:]:
            if all(c in hexdigits for c in line [:4]):
                try: m_array = bytearray.fromhex(line[6:54])
                except: break
                binary_html += m_array
            else:
                #http HEADER is delimited from HTTP body with '\r\n\r\n'
                if binary_html.find('\r\n\r\n') == -1:
                    return -1
                break
        return binary_html.split('\r\n\r\n', 1)[1]
