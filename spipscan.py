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
# Version is in the header (for almost all versions)


def detect_version(req):
    if ('composed-by' in req.headers):
        res = detect_version_with_header(req.headers['composed-by'])
        if (res):
            return
        else:
            res = detect_version_in_html(req.content)
            if (res):
                return
            else:
                print "Are you sure it's an SPIP Install ?"
                raise Exception('Are you sure it is an SPIP install ?')
            

def detect_version_in_html(content):
    global major_version
    global intermediary_version
    global minor_version

    regex_version_spip = re.search(r"generator\" content=\"SPIP ((\d+).?(\d+)?.?(\d+)?)", content)
    try:
        major_version = regex_version_spip.group(2)
        intermediary_version = regex_version_spip.group(3)
        minor_version = regex_version_spip.group(4)

        print "[!] Version (in HTML) is : " + str(major_version) + "." + str(intermediary_version) + "." + str(minor_version)
        return True
    except:
        display_message("[-] Unable to find the version in the HTML")
        return False

def detect_version_with_header(header_composed_by):
    global major_version
    global intermediary_version
    global minor_version

    regex_version_spip = re.search(
        r"SPIP (\d+).(\d+).(\d+)", header_composed_by)
    try:
        major_version = regex_version_spip.group(1)
        intermediary_version = regex_version_spip.group(2)
        minor_version = regex_version_spip.group(3)

        print "[!] Version (in Headers) is : " + str(major_version) + "." + str(intermediary_version) + "." + str(minor_version)
        return True
    except:
        display_message("[-] Unable to find the version in the headers")
        return False


# Detect the plugins/themes folder of a SPIP install
# Moreover, if there's directory listing enabled, it recovers the plugins/themes
# And it does not do bruteforce attack on the retrieved elements.


def detect_folder(url, isForPlugins):
    global folder_themes
    global folder_plugins
    global opts

    plugins_folders = ['plugins/', 'plugins-dist/']
    themes_folders = ['themes/', 'theme/', 'Themes/', 'Theme/']

    folders = []

    if (isForPlugins):
        folders = plugins_folders
    else:
        folders = themes_folders


    for folder in folders:
        url_to_visit = url + folder
        req = requests.get(url_to_visit, timeout=10)

        # code for both status code 200/403
        if (req.status_code == 200 or req.status_code == 403):
            if (isForPlugins):
                folder_plugins = folder
                print "[!] Plugin folder is : " + folder_plugins
                if (req.status_code == 200):
                    opts.bruteforce_plugins_file = None
            else:
                folder_themes = folder
                print "[!] Theme folder is : " + folder_themes
                if (req.status_code == 200):
                    opts.bruteforce_themes_file = None

        # code only for 200 (directory listing)
        if (req.status_code == 200):
            url = url + folder # set up the url
            iterate_directory_listing(url, req.content)
            return True

        if (req.status_code == 403):
            print "[-] Access forbidden on folder."
            return True

    return False

# Function to iterate on results if there's a directory listing
# will then (try to) detect the version of the plugin/theme

def iterate_directory_listing(url, content):
    print "[!] Directory listing on folder !"
    soup = BeautifulSoup(content)
    links_to_plugins = soup('a')
    for link in links_to_plugins:
        # grabbing the folder of the plugin
        try:
            regex_plugin = re.search(r"href=\"(\w+/)\">\s?(\w+)/<", str(link))
            folder_plugin = regex_plugin.group(1)
            name_plugin = regex_plugin.group(2)
            detect_version_of_plugin_or_theme_by_folder_name(url, folder_plugin)
        except:
            pass

# Detect the version of either a plugin and theme.
# Structure is the same, folder contains either plugin.xml or paquet.xml


def detect_version_of_plugin_or_theme_by_folder_name(url, folder):
    url_folder = url + folder + "plugin.xml"
    # HTTP GET to get the version of the plugin
    req_plugin_xml = requests.get(url_folder, timeout=10)
    display_message("[-] Trying : " + url_folder)
    if (req_plugin_xml.status_code == 200):
        regex_version_plugin = re.search(
            r"<version>\s*?(\d+(.\d+)?(.\d+)?)\s*?</version>", req_plugin_xml.content, re.S)
        print "[!] Plugin " + folder[:-1] + " detected. Version : " + str(regex_version_plugin.group(1))
        display_message("URL : " + url_folder)
    else:
        url_folder = url + folder + "paquet.xml"
        # HTTP GET to get the version of the plugin
        req_plugin_xml = requests.get(url_folder, timeout=10)
        display_message("[-] Trying : " + url_folder)
        if (req_plugin_xml.status_code == 200):
            regex_version_plugin = re.search(
                r"version=\"\s*?(\d+(.\d+)?(.\d+)?)\s*?\"", req_plugin_xml.content, re.S)
            print "[!] Plugin " + folder[:-1] + " detected. Version : " + str(regex_version_plugin.group(1))
            display_message("URL : " + url_folder)
        else:
            pass

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
                i =               i = i+ 1

# This function allows you to do brute force to search for folders
# This function is used to bruteforce Plugin/Theme names 


def bruteforce_folder(url, filename, isForPlugins):
    # uri for the plugins folder
    global folder_plugins
    global folder_themes

    # If we haven't been able to detect the plugins folder, we exit
    if (isForPlugins and folder_plugins is None):
        return

    # If we haven't been able to detect the themes folder, we exit
    if (isForPlugins is False and folder_themes is None):
        return

    if (isForPlugins is False and folder_themes is not None):
        url = url + folder_themes

    if (isForPlugins and folder_plugins is not None):
        url = url + folder_plugins


    folders = []
    with open(filename) as f:
        folders = f.readlines()

    # removing new line
    folders = [remove_new_line_from_name(name, '/') for name in folders]
    for folder in folders:
        detect_version_of_plugin_or_theme_by_folder_name(url, folder)    

# Display function to only print message
# if verbose mode is ON


def display_message(m):
    global opts

    if (opts.verbose):
        print m


# option parser
parser = optparse.OptionParser()
parser.add_option('--website', help='Website to pentest', dest='website')
parser.add_option('--path', help='Path for webapp (default : "/")', dest='path', default='/')
parser.add_option('--plugins', help='Detect plugins installed', dest='detect_plugins', default=False, action='store_true')
parser.add_option('--themes', help='Detect themes installed', dest='detect_themes', default=False, action='store_true')
parser.add_option('--version', help='Detect version', dest='detect_version', default=False, action='store_true')
parser.add_option('--vulns', help='Detect possible vulns', dest='detect_vulns', default=False, action='store_true')
parser.add_option('--bruteforce_plugins_file', help='Bruteforce plugin file (eg. plugins_name.db)', dest='bruteforce_plugins_file', default=None)
parser.add_option('--bruteforce_themes_file', help='Bruteforce theme file (eg. themes_name.db)', dest='bruteforce_themes_file', default=None)
parser.add_option('--verbose', help='Verbose mode', dest='verbose', default=False, action='store_true')


if (len(sys.argv) <= 2):
    parser.print_help()
else:
    (opts, args) = parser.parse_args()

    url = opts.website + opts.path
    display_message("Application is located here : " + url)

    if (opts.detect_version or opts.detect_vulns):
        req = requests.get(url, timeout=10)
        detect_version(req)

    if (opts.detect_plugins or opts.bruteforce_plugins_file is not None):
        if not detect_folder(url, True):
            print "[-] We haven't been able to locate the plugins folder"

    if (opts.detect_themes or opts.bruteforce_themes_file is not None):
        if not detect_folder(url, False):
            print "[-] We haven't been able to locate the themes folder"

    # detect plugin will do brute force attack if it finds a HTTP 403
    # (Restricted)
    # opts.detect_plugins is False and 
    if (opts.bruteforce_plugins_file is not None and folder_plugins is not None):
        bruteforce_folder(url, opts.bruteforce_plugins_file, True)

    # brute force themes folder if 403 also
    if (opts.bruteforce_themes_file is not None and folder_themes is not None):
        bruteforce_folder(url, opts.bruteforce_themes_file, False)

    if (opts.detect_vulns):
        detect_vulnerabilities()
