#! /usr/bin/env python
# -*- coding: utf-8 -*-

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

plugins = {}

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


def detect_plugins_in_header(req):
    regex_plugins = re.search(r"\+\s([\w(\.),]+)", req.headers['composed-by'])
    try:
        plugins = regex_plugins.group(1).split(',')
        for plugin in plugins:
            plugin_name = plugin.split('(')[0]
            plugin_version = plugin.split('(')[1][:-1]
            insert_discovered_plugin(plugin_name, plugin_version)
    except:
        display_message("[-] We haven't been able to get plugins in Header")


def insert_discovered_plugin(plugin_name, plugin_version):
    global plugins

    if (plugin_name not in plugins):
        plugins[plugin_name] = plugin_version
        print "[!] Plugin " + plugin_name + " detected. Version : " + plugin_version

# Detect the plugins/themes folder of a SPIP install
# Moreover, if there's directory listing enabled, it recovers the plugins/themes
# And it does not do bruteforce attack on the retrieved elements.


def detect_folder_for_themes_and_plugins(url, isForPlugins):
    global folder_themes
    global folder_plugins
    global opts

    plugins_folders = ['plugins/', 'plugins-dist/']
    themes_folders = ['themes/', 'theme/', 'Themes/', 'Theme/']

    folders = []

    if (isForPlugins):
        folders = plugins_folders
        display_message('[-] Trying to detect folder for plugins')
    else:
        folders = themes_folders
        display_message('[-] Trying to detect folder for themes')


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

# Detect sensitive folders/files for the specified SPIP install
# Will check the status code and define if the resource might be available or not 

def detect_sensitive_folders(url):
    folders = ['IMG/', 'prive/', 'local/', 'config/', 'local/', 'config/ecran_securite.php']

    for folder in folders:
        url_to_visit = url + folder
        req = requests.get(url_to_visit, timeout=10)

        # code only for 200 (might be directory listing)
        if (req.status_code == 200):
            if ("Index of" in req.content):
                print "[!] Directory listing on folder : " + folder
            else:
                display_message("[-] Folder/File " + folder + " might be interesting")
        elif (req.status_code == 403):
            print "[-] Access forbidden on folder/file " + folder + "."


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
            insert_discovered_plugin(folder[:-1], str(regex_version_plugin.group(1)))
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
    with open('./db/spip_vulns.db') as f:
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
                i = i+ 1

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


# enumerate users
def enumerate_users(url, file_logins):

    logins = []
    with open(file_logins) as f:
        logins = f.readlines()

    # removing new line
    logins = [remove_new_line_from_name(name) for name in logins]

    url_login = url + 'spip.php?page=login'
    display_message("Accessing " + url_login)
    req = requests.get(url_login)

    soup = BeautifulSoup(req.content)
    inputTag = soup.findAll(attrs={"name": "formulaire_action_args"})
    valueTag = inputTag[0]['value']
    display_message("Form action args grabbed : " + valueTag)

    # craft the POST request
    req_login = {}
    req_login['page'] = 'login'
    req_login['formulaire_action'] = 'login'
    req_login['formulaire_action_args'] = valueTag
    req_login['session_password_md5'] = ''
    req_login['next_session_password_md5'] = ''
    req_login['password'] = 'spipscan'

    for login in logins:
        req = req_login.copy()
        req['var_login'] = login
        req = requests.post(url_login, data=req)
        if (contains_unknown_login(req.content)):
            display_message("[-] Tried login : " + login)
        else:
            print "[!] Login found : " + login


# Function to check if the response contains
# a message saying that the login exists or not

def contains_unknown_login(response):

    # Feel free to add more if it's not already in it
    unknown_message = ['je nepoznat',
                        'desconegut',
                        'pa konu',
                        'li se pa rokoni',
                        'je nezn&aacute;m&aacute;',
                        'kendes ikke.',
                        'unbekannt',
                        'is unknown',
                        'estas nekonata',
                        'es desconocido',
                        'identifikatzailea ezezaguna da',
                        'Ny&iacute;k&#596;&#770; &aacute;',
                        'est inconnu',
                        '&eacute; desco&ntilde;ecido',
                        'azonos&iacute;t&oacute; ismeretlen',
                        'tidak dikenal',
                        'risulta inesistente',
                        'risulta inesistente',
                        'is niet bekend',
                        'z-es inconegut',
                        'inconegut',
                        'es desconoissut',
                        'desconhecido']
    for message in unknown_message:
        if (message in response):
            return True

    return False


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
parser.add_option('--users', help='Bruteforce user logins', dest='bruteforce_user_logins', default=False, action='store_true')
parser.add_option('--sensitive_folders', help='Detect sensitive folders', dest='detect_sensitive_folders', default=False, action='store_true')
parser.add_option('--version', help='Detect version', dest='detect_version', default=False, action='store_true')
parser.add_option('--vulns', help='Detect possible vulns', dest='detect_vulns', default=False, action='store_true')
parser.add_option('--bruteforce_plugins_file', help='Bruteforce plugin file (eg. plugins_name.db)', dest='bruteforce_plugins_file', default=None)
parser.add_option('--bruteforce_themes_file', help='Bruteforce theme file (eg. themes_name.db)', dest='bruteforce_themes_file', default=None)
parser.add_option('--bruteforce_logins_file', help='Bruteforce login file (eg. user_logins.db)', dest='bruteforce_logins_file', default=None)
parser.add_option('--verbose', help='Verbose mode', dest='verbose', default=False, action='store_true')


if (len(sys.argv) <= 2):
    parser.print_help()
else:
    (opts, args) = parser.parse_args()

    url = opts.website + opts.path
    display_message("Application is located here : " + url)

    if (opts.detect_version or opts.detect_vulns or opts.bruteforce_user_logins or opts.detect_plugins):
        req = requests.get(url, timeout=10)
        detect_version(req)

    if (opts.detect_plugins or opts.bruteforce_plugins_file is not None):
        display_message("[-] Trying to detect plugins in Header")
        detect_plugins_in_header(req)        
        if not detect_folder_for_themes_and_plugins(url, True):
            print "[-] We haven't been able to locate the plugins folder"

    if (opts.detect_themes or opts.bruteforce_themes_file is not None):
        if not detect_folder_for_themes_and_plugins(url, False):
            print "[-] We haven't been able to locate the themes folder"

    # detect plugin will do brute force attack if it finds a HTTP 403
    # (Restricted)
    if (opts.bruteforce_plugins_file is not None and folder_plugins is not None):
        bruteforce_folder(url, opts.bruteforce_plugins_file, True)

    # brute force themes folder if 403 also
    if (opts.bruteforce_themes_file is not None and folder_themes is not None):
        bruteforce_folder(url, opts.bruteforce_themes_file, False)

    if (opts.bruteforce_user_logins and opts.bruteforce_logins_file is not None):
        if (major_version == "2" and intermediary_version == "0"):
            enumerate_users(url, opts.bruteforce_logins_file)
        else:
            print "This feature is only available for versions 2.0.X"
        

    if (opts.detect_sensitive_folders):
        detect_sensitive_folders(url)

    if (opts.detect_vulns):
        detect_vulnerabilities()
