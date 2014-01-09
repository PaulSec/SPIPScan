import optparse
import sys
import requests
import re

def detect_version(header_composed_by):
    regex_version_spip = re.search(r"SPIP (\d+).(\d+).(\d+)", header_composed_by)
    try:
        major_version = regex_version_spip.group(1)
        intermediary_version = regex_version_spip.group(2)
        minor_version = regex_version_spip.group(3)
        print "version is : " + str(major_version) + "." + str(intermediary_version) + "." + str(minor_version)
    except:
        print "unable to find the version"
        pass

# option parser
parser = optparse.OptionParser()
parser.add_option('--website', help='Website to pentest', dest='website')
parser.add_option('--path', help='Path for webapp (default : "/")', dest='path', default='/')
# parser.add_option('--v', help='Verbose', dest='verbose', default=False)

if (len(sys.argv) <= 1):
    parser.print_help()
else:
    (opts, args) = parser.parse_args()

    url = opts.website + opts.path
    print "Accessing " + url
    req = requests.get(url, timeout=5)

    detect_version(req.headers['composed-by'])
 