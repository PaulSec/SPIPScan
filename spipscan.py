import optparse
import sys
import requests
import re
from bs4 import BeautifulSoup

def detect_version(header_composed_by):
    regex_version_spip = re.search(r"SPIP (\d+).(\d+).(\d+)", header_composed_by)
    try:
        major_version = regex_version_spip.group(1)
        intermediary_version = regex_version_spip.group(2)
        minor_version = regex_version_spip.group(3)
        print "[!] version is : " + str(major_version) + "." + str(intermediary_version) + "." + str(minor_version)
    except:
        print "[-] unable to find the version"
        pass

def detect_plugins(url):
    plugins_folder_uri = "plugins/"
    url = url + plugins_folder_uri
    print "Accessing " + url
    req = requests.get(url, timeout=5)

    if (req.status_code == 200):
        # folder might be viewable
        # gonna iterate on the different plugins
        print "[!] folder plugins/ is accessible"
        soup = BeautifulSoup(req.content)
        links_to_plugins = soup('a')
        for link in links_to_plugins:
            # grabbing the folder of the plugin
            try:
                regex_plugin = re.search(r"href=\"(\w+/)\"> (\w+)/<", str(link))
                folder_plugin = regex_plugin.group(1)
                name_plugin = regex_plugin.group(2)
                detect_version_by_plugin_name(url, folder_plugin)
            except:
                pass
            
    elif (req.status_code == 403):
        # folder might exist but not accessible
        # gonna try to detect plugins with brute force attack
        print "[-] folder plugins/ is forbidden"
    elif (req.status_code == 404):
        # folder seems to not exist
        print "[-] folder plugins/ does not exist"
    else:
        print "While accessing " + url + ", the status code is : " + str(req.status_code)


def remove_new_line_from_name(name):
    return name[:-1] + '/'

def brute_force_folder_plugins(url, name_file):
    # uri for the plugins folder
    plugins_folder_uri = "plugins/"
    url = url + plugins_folder_uri

    folders = []
    with open(name_file) as f:
        folders = f.readlines()

    # removing new line 
    folders = [remove_new_line_from_name(name) for name in folders]
    for folder in folders:
        print "[-] Trying : " + url + folder
        detect_version_by_plugin_name(url, folder)

def detect_version_by_plugin_name(url, folder):
    try:
        url_plugin = url + folder + "plugin.xml"
        # HTTP GET to get the version of the plugin
        req_plugin_xml = requests.get(url_plugin, timeout=5)
        regex_version_plugin = re.search(r"<version>(\d+(.\d+)?(.\d+)?)</version>", req_plugin_xml.content)
        print "[!] Plugin " + folder + " detected. Version : " + str(regex_version_plugin.group(1))
        print "URL : " + url_plugin
    except:
        try:
            url_plugin = url + regex_plugin.group(1) + "paquet.xml"
            # HTTP GET to get the version of the plugin
            req_plugin_xml = requests.get(url_plugin, timeout=5)
            regex_version_plugin = re.search(r"version=\"(\d+(.\d+)?(.\d+)?)\"", req_plugin_xml.content)
            print "[!] Plugin " + folder + " detected. Version : " + str(regex_version_plugin.group(1))
            print "URL : " + url_plugin
        except:
            pass    

# option parser
parser = optparse.OptionParser()
parser.add_option('--website', help='Website to pentest', dest='website')
parser.add_option('--path', help='Path for webapp (default : "/")', dest='path', default='/')
parser.add_option('--plugins', help='Detect plugins installed', dest='detect_plugins', default=False, action='store_true')
parser.add_option('--version', help='Detect version', dest='detect_version', default=False, action='store_true')
parser.add_option('--brute_force_plugins', help='Bruteforce plugin file (eg. plugins_name.txt)', dest='brute_force_plugins', default=None)
# parser.add_option('--v', help='Verbose', dest='verbose', default=False)

if (len(sys.argv) <= 1):
    parser.print_help()
else:
    (opts, args) = parser.parse_args()

    url = opts.website + opts.path

    if (opts.detect_version):
        print "Accessing " + url
        req = requests.get(url, timeout=5)
        detect_version(req.headers['composed-by']) 

    if (opts.detect_plugins):
        detect_plugins(url)

    if (opts.brute_force_plugins is not None):
        brute_force_folder_plugins(url, opts.brute_force_plugins)