Instructions for Windows users (auditee role) installing into Firefox 29.0.

Step 1: Use "Download Zip" on github and install the tlsnotary project into any chosen directory, we'll call it "dir1".

Step 2: Shut down Firefox and make sure no Firefox process is running.

Step 3: Find your firefox.exe program; usually it is in C:\Program Files (x86)\Mozilla Firefox\firefox.exe". In the same directory find files "nss3.dll" and "softokn3.dll". Copy these two files to any backup directory.

Step 4: Go into dir1\tlsnotary\data\libraries\ and find files nss3.dll and softokn3.dll. Verify the gpg signatures using "gpg --verify nss3.dll.asc nss3.dll" (you need to install gpg of course), and the same for softokn3. The signature should correspond to key ID E9A3197A.

Step 5: Once the signatures are verified, copy these two files into C:\Program Files (x86)\Mozilla Firefox.

Step 6. You can test by double clicking the file: dir1\tlsnotary\windows-auditee.bat

Step 7: If all is well, you will see a webpage with a "Connect to IRC" button on it. Next, open a new tab and go to : https://addons.mozilla.org/en-US/firefox/addon/the-addon-bar/ and click "Add to Firefox". Once it is installed, go to the "Open Menu" (the three horizontal lines button on the top right), click it and click "Customize". You should see on the left two grey buttons "RECORD" and "STOP" next to each other. Carefully (wait for the hand icon) drag the RECORD button (the STOP will follow it) onto the x in the bottom left corner, and then drop. You should now "Exit customize" and see the RECORD and STOP buttons in the AddonBar.

tlsnotary should now operate normally.
