SPIPScan
========

SPIP (CMS) Scanner for penetration testing purpose written in Python

This tool has been designed to perform detection of SPIP installs during penetration testing. 
Currently, the tool detects the version of the SPIP install and tries to detect if the platform uses some of the top 30 plugins (listed on their website)

Here are some usage :


Version detection
========
python spipscan.py --website=http://website.com --version


Plugins detection
========
python spipscan.py --website=http://website.com --plugins

python spipscan.py --website=http://website.com --plugins --bruteforce_plugins=plugins_name.txt

The second example performs brute force detection as well. 


Plugins bruteforce
========
python spipscan.py --website=http://website.com --bruteforce_plugins=plugins_name.txt



