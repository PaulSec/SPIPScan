SPIPScan
========

SPIP (CMS) Scanner for penetration testing purpose written in Python, and released under MIT License.

This tool has been designed to perform detection of SPIP installs during penetration testing. 
Currently, the tool detects the version of the SPIP install and tries to detect if the platform uses some of the top 30 plugins (listed on their website)


Usage
========

$ python spipscan.py <br />
Usage: spipscan.py [options]<br />
<br />
Options:<br />
  -h, --help            show this help message and exit<br />
  --website=WEBSITE     Website to pentest<br />
  --path=PATH           Path for webapp (default : "/")<br />
  --plugins             Detect plugins installed<br />
  --version             Detect version<br />
  --vulns               Detect possible vulns<br />
  --bruteforce_plugins_file=BRUTEFORCE_PLUGINS_FILE<br />
                        Bruteforce plugin file (eg. plugins_name.txt)<br />



Version detection
========
$ python spipscan.py --website=http://127.0.0.1 --version<br />
Accessing http://127.0.0.1/<br />
[!] Version is : 3.0.13<br />
[!] Plugin folder is : plugins-dist/<br />



Plugins detection
========
$ python spipscan.py --website=http://127.0.0.1 --plugins | grep [!]<br />
[!] Plugin folder is : plugins-dist/<br />
[!] folder plugins-dist/ is accessible<br />
[!] Plugin breves detected. Version : 1.3.5<br />
[!] Plugin compagnon detected. Version : 1.4.1<br />
[!] Plugin compresseur detected. Version : 1.8.6<br />
[!] Plugin dump detected. Version : 1.6.7<br />
[!] Plugin filtres_images detected. Version : 1.1.7<br />
[!] Plugin forum detected. Version : 1.8.29<br />
[!] Plugin jquery_ui detected. Version : 1.8.21<br />
[!] Plugin mediabox detected. Version : 0.8.4<br />
[!] Plugin medias detected. Version : 2.7.51<br />
[!] Plugin mots detected. Version : 2.4.10<br />
[!] Plugin msie_compat detected. Versoin : 1.2.0<br />
[!] Plugin organiseur detected. Version : 0.8.10<br />
[!] Plugin petitions detected. Version : 1.4.4<br />
[!] Plugin porte_plume detected. Version : 1.12.4<br />
[!] Plugin revisions detected. Version : 1.7.6<br />
[!] Plugin safehtml detected. Version : 1.4.0<br />
[!] Plugin sites detected. Version : 1.7.10<br />
[!] Plugin squelettes_par_rubrique detected. Version : 1.1.1<br />
[!] Plugin statistiques detected. Version : 0.4.19<br />
[!] Plugin svp detected. Version : 0.80.18<br />
[!] Plugin textwheel detected. Version : 0.8.17<br />
[!] Plugin urls_etendues detected. Version : 1.4.15<br />
[!] Plugin vertebres detected. Version : 1.2.2<br />


The next example performs brute force to detect existing plugins :<br />

$ python spipscan.py --website=http://website.com --plugins --bruteforce_plugins=plugins_name.db



Plugins bruteforce
========
$ python spipscan.py --website=http://website.com --bruteforce_plugins=plugins_name.db<br />


Vulnerabilities identification
========
$ python spipscan.py --website=http://127.0.0.1 --vulns<br />
Accessing http://127.0.0.1/<br />
[!] Version is : 2.1.12<br />
[!] Plugin folder is : plugins/<br />
[!] Potential Vulnerability : (versions : 2.0.21/2.1.16/3.0.3), SPIP connect Parameter PHP Injection, details : http://www.exploit-db.com/exploits/27941/

