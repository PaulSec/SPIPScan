import optparse
import sys
import requests
import re
from bs4 import BeautifulSoup

major_version = 0
intermediary_version = 0
minor_version = 0
folder_plugins = None
folder_themes = None

# Detect the version of a SPIP install


def detect_version(header_composed_by):
    global major_version
    global intermediary_version
    global minor_version

    regex_version_spip = re.search(
        r"SPIP (\d+).(\d+).(\d+)", header_composed_by)
    try:
        major_version = regex_version_spip.group(1)
        intermediary_version = regex_version_spip.group(2)
        minor_version = regex_version_spip.group(3)

        print "[!] Version is : " + str(major_version) + "." + str(intermediary_version) + "." + str(minor_version)
    except:
        print "[-] Unable to find the version"
        pass

# Detect the theme folder of a SPIP install


def detect_themes_folder(url):
    global folder_themes

    folders = ['themes/', 'theme/', 'Themes/', 'Theme/']

    for folder in folders:
        url_to_visit = url + folder
        req = requests.get(url_to_visit, timeout=10)

        if (req.status_code == 200 or req.status_code == 403):
            folder_themes = folder
            print "[!] Theme folder is : " + folder_themes
            return True
        else:
            pass

    return False


# Detect the plugin folder of a SPIP install


def detect_plugins_folder(url):
    global folder_plugins

    folders = ['plugins/', 'plugins-dist/']

    for folder in folders:
        url_to_visit = url + folder
        req = requests.get(url_to_visit, timeout=10)

        if (req.status_code == 200 or req.status_code == 403):
            folder_plugins = folder
            print "[!] Plugin folder is : " + folder_plugins
            return True
        else:
            pass

    return False

# Detect version of a plugin name (folder is the name of the folder of the
# plugin)


def detect_version_by_plugin_name(url, folder):
    url_plugin = url + folder + "plugin.xml"
    # HTTP GET to get the version of the plugin
    req_plugin_xml = requests.get(url_plugin, timeout=10)
    if (req_plugin_xml.status_code == 200):
        regex_version_plugin = re.search(
            r"<version>\s*?(\d+(.\d+)?(.\d+)?)\s*?</version>", req_plugin_xml.content, re.S)
        print "[!] Plugin " + folder[:-1] + " detected. Version : " + str(regex_version_plugin.group(1))
        print "URL : " + url_plugin
    else:
        url_plugin = url + folder + "paquet.xml"
        # HTTP GET to get the version of the plugin
        req_plugin_xml = requests.get(url_plugin, timeout=10)
        if (req_plugin_xml.status_code == 200):
            regex_version_plugin = re.search(
                r"version=\"\s*?(\d+(.\d+)?(.\d+)?)\s*?\"", req_plugin_xml.content, re.S)
            print "[!] Plugin " + folder[:-1] + " detected. Version : " + str(regex_version_plugin.group(1))
            print "URL : " + url_plugin
        else:
            pass

# Detect plugins by bruteforcing them with a file


def detect_plugins(url, bruteforce_file):
    global folder_plugins

    # If we haven't been able to detect the plugins folder, we exit
    if (folder_plugins is None):
        return

    url = url + folder_plugins
    print "Accessing " + url
    req = requests.get(url, timeout=10)

    # folder might be viewable
    # gonna iterate on the different plugins
    if (req.status_code == 200):
        print "[!] folder " + folder_plugins + " is accessible"
        soup = BeautifulSoup(req.content)
        links_to_plugins = soup('a')
        for link in links_to_plugins:
            # grabbing the folder of the plugin
            try:
                regex_plugin = re.search(
                    r"href=\"(\w+/)\">\s?(\w+)/<", str(link))
                folder_plugin = regex_plugin.group(1)
                name_plugin = regex_plugin.group(2)
                detect_version_by_plugin_name(url, folder_plugin)
            except:
                pass

    # folder might exist but not accessible
    # gonna try to detect plugins with brute force attack
    elif (req.status_code == 403):
        print "[-] folder " + folder_plugins + " is forbidden"
        if (bruteforce_file is not None):
            # bruteforce the plugins folder
            bruteforce_folder_plugins(url, bruteforce_file)

# Remove new line character and replace it with another one if specified


def remove_new_line_from_name(name, char=''):
    return name[:-1] + char

# Detect vulnerabilities of the SPIP website


def detect_vulnerabilities():
    global major_version
    global intermediary_version
    global minor_version

    vulns = []
    with open('spip_vulns.db') as f:
        vulns = f.readlines()

    # removing new line
    vulns = [remove_new_line_from_name(vuln) for vuln in vulns]

    # parsing the db to check if there's any vuln
    for vuln in vulns:
        vals = vuln.split(';;')
        versions_vuln = vals[0]
        description_vuln = vals[1]
        url_vuln = vals[2]
        version_vuln = versions_vuln.split('/')
        for version in version_vuln:
            tmp = version.split('.')
            i = 0
            while i < len(tmp):
                if (i == 0 and tmp[i] != major_version):
                    break
                if (i == 1 and tmp[i] != intermediary_version):
                    break

                if (i == 1 and tmp[i] == intermediary_version and (i + 1) > len(tmp)):
                    print "[!] Potential Vulnerability : (versions : " + versions_vuln + "), " + description_vuln + ", details : " + url_vuln
                    break

                if ((i == 2) and (int(tmp[i]) >= int(minor_version))):
                    print "[!] Potential Vulnerability : (versions : " + versions_vuln + "), " + description_vuln + ", details : " + url_vuln
                    break
                i = i + 1


def bruteforce_folder_plugins(url, name_file):
    # uri for the plugins folder
    global folder_plugins

    # If we haven't been able to detect the plugins folder, we exit
    if (folder_plugins is None):
        return

    folders = []
    with open(name_file) as f:
        folders = f.readlines()

    # removing new line
    folders = [remove_new_line_from_name(name, '/') for name in folders]
    for folder in folders:
        print "[-] Trying : " + url + folder
        detect_version_by_plugin_name(url, folder)

# option parser
parser = optparse.OptionParser()
parser.add_option('--website', help='Website to pentest', dest='website')
parser.add_option('--path', help='Path for webapp (default : "/")',
                  dest='path', default='/')
parser.add_option('--plugins', help='Detect plugins installed',
                  dest='detect_plugins', default=False, action='store_true')
parser.add_option('--themes', help='Detect themes installed',
                  dest='detect_themes', default=False, action='store_true')
parser.add_option('--version', help='Detect version',
                  dest='detect_version', default=False, action='store_true')
parser.add_option('--vulns', help='Detect possible vulns',
                  dest='detect_vulns', default=False, action='store_true')
parser.add_option(
    '--bruteforce_plugins_file', help='Bruteforce plugin file (eg. plugins_name.txt)',
    dest='bruteforce_plugins_file', default=None)


if (len(sys.argv) <= 2):
    parser.print_help()
else:
    (opts, args) = parser.parse_args()

    url = opts.website + opts.path
    print "Application is located here : " + url

    if (opts.detect_version or opts.detect_vulns):
        req = requests.get(url, timeout=10)
        detect_version(req.headers['composed-by'])

    if (opts.detect_plugins or opts.bruteforce_plugins_file is not None):
        if not detect_plugins_folder(url):
            print "[-] We haven't been able to locate the plugins folder"

    if (opts.detect_themes):
        if not detect_themes_folder(url):
            print "[-] We haven't been able to locate the themes folder"

    # detect plugin will do brute force attack if it finds a HTTP 403
    # (Restricted)
    # opts.detect_plugins is False and 
    if (opts.bruteforce_plugins_file is not None and folder_plugins is not None):
        bruteforce_folder_plugins(url, opts.bruteforce_plugins_file)

    if (opts.detect_vulns):
        detect_vulnerabilities()
