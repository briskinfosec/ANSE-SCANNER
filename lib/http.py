def http(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[92m
+------------------------------------+-----------------------------------------+-----------------------------------+--------------------------------
| +Choose your NSE script for HTTP:  |                                         |                                   |
| [01] http-adobe-coldfusion-apsa1301| [32] http-errors                        | [63] http-open-proxy              |  [94] http-virustotal
| [02] http-affiliate-id             | [33] http-exif-spider                   | [64] http-open-redirect           |  [95] http-vlcstreamer-ls
| [03] http-apache-negotiation       | [34] http-favicon                       | [65] http-passwd                  |  [96] http-vmware-path-vuln
| [04] http-apache-server-status     | [35] http-feed                          | [66] http-php-version             |  [97] http-vuln-cve2006-3392
| [05[ http-aspnet-debug             | [36] http-fetch                         | [67] http-phpmyadmin-dir-traversal|  [98] http-vuln-cve2009-3960
| [06] http-auth-finder              | [37] http-fileupload-exploiter          | [68] http-phpself-xss             |  [99] http-vuln-cve2010-0738
| [07] http-auth                     | [38] http-form-brute                    | [69] http-proxy-brute             | [100] http-vuln-cve2010-2861
| [08] http-avaya-ipoffice-users     | [39] http-form-fuzzer                   | [70] http-put                     | [101] http-vuln-cve2011-3192
| [09] http-awstatstotals-exec       | [40] http-frontpage-login               | [71] http-qnap-nas-info           | [102] http-vuln-cve2011-3368
| [10] http-axis2-dir-traversal      | [41] http-generator                     | [72] http-referer-checker         | [103] http-vuln-cve2012-1823
| [11] http-backup-finder            | [42] http-git                           | [73] http-rfi-spider              | [104] http-vuln-cve2013-0156
| [12] http-barracuda-dir-traversal  | [43] http-gitweb-projects-enum          | [74] http-robots.txt              | [105] http-vuln-cve2013-6786
| [13] http-brute                    | [44] http-google-malware                | [75] http-robtex-reverse-ip       | [106] http-vuln-cve2013-7091
| [14] http-cakephp-version          | [45] http-grep                          | [76] http-robtex-shared-ns        | [107] http-vuln-cve2014-2126
| [15] http-chrono                   | [46] http-headers                       | [77] http-server-header           | [108] http-vuln-cve2014-2127
| [16] http-cisco-anyconnect         | [47] http-huawei-hg5xx-vuln             | [78] http-shellshock              | [109] http-vuln-cve2014-2128
| [17] http-coldfusion-subzero       | [48] http-icloud-findmyiphone           | [79] http-sitemap-generator       | [110] http-vuln-cve2014-2129
| [18] http-comments-displayer       | [49] http-icloud-sendmsg                | [80] http-slowloris-check         | [111] http-vuln-cve2014-3704
| [19] http-config-backup            | [50] http-iis-short-name-brute          | [81] http-slowloris               | [112] http-vuln-cve2014-8877
| [20] http-cors                     | [51] http-iis-webdav-vuln               | [82] http-sql-injection           | [113] http-vuln-cve2015-1427
| [21] http-cross-domain-policy      | [52] http-internal-ip-disclosure        | [83] http-stored-xss              | [114] http-vuln-cve2015-1635
| [22] http-csrf                     | [53] http-joomla-brute                  | [84] http-svn-enum                | [115] http-vuln-misfortune-cookie
| [23] http-date                     | [54] http-litespeed-sourcecode-download | [85] http-svn-info                | [116] http-vuln-wnr1000-creds
| [24] http-default-accounts         | [55] http-ls                            | [86] http-title                   | [117] http-waf-detect
| [25] http-devframework             | [56] http-majordomo2-dir-traversal      | [87] http-tplink-dir-traversal    | [118] http-waf-fingerprint
| [26] http-dlink-backdoor           | [57] http-malware-host                  | [88] http-trace                   | [119] http-webdav-scan
| [27] http-dombased-xss             | [58] http-mcmp                          | [89] http-traceroute              | [120] http-wordpress-brute
| [28] http-domino-enum-passwords    | [59] http-method-tamper                 | [90] http-unsafe-output-escaping  | [121] http-wordpress-enum
| [29] http-drupal-enum-users        | [60] http-methods                       | [91] http-useragent-tester        | [122] http-wordpress-users
| [30] http-drupal-enum              | [61] http-mobileversion-checker         | [92] http-userdir-enum            | [123] http-xssed,
| [31] http-enum                     | [62] http-ntlm-info                     | [93] http-vhosts                  |  [0]  back
+------------------------------------+-----------------------------------------+-----------------------------------+-------------------------------\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-adobe-coldfusion-apsa1301

Script types: portrule
Categories: exploit, vuln
Download: http://nmap.org/svn/scripts/http-adobe-coldfusion-apsa1301.nse

User Summary
Attempts to exploit an authentication bypass vulnerability in Adobe Coldfusion servers to retrieve a valid
administrator's session cookie.

Script Arguments
http-adobe-coldfusion-apsa1301.basepath
URI path to administrator.cfc. Default: /CFIDE/adminapi/
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script http-adobe-coldfusion-apsa1301 <target>
nmap -p80 --script http-adobe-coldfusion-apsa1301 --script-args basepath=/cf/adminapi/ <target>

Default Option Used in script:
nmap -sV  -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-adobe-coldfusion-apsa1301 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-adobe-coldfusion-apsa1301 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-affiliate-id

Script types:
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/http-affiliate-id.nse

User Summary
Grabs affiliate network IDs (e.g. Google AdSense or Analytics, Amazon Associates, etc.) from a web page.
These can be used to identify pages with the same owner.
If there is more than one target using an ID, the postrule of this script shows the ID along with a list of the targets
using it.

Supported IDs:
    Google Analytics
    Google AdSense
    Amazon Associates

Script Arguments
http-affiliate-id.url-path
The path to request. Defaults to /.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-affiliate-id --script-args http-affiliate-id.url-path=/website <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-affiliate-id'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-affiliate-id -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-apache-negotiation

Script types: portrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/http-apache-negotiation.nse

User Summary
Checks if the target http server has mod_negotiation enabled. This feature can be leveraged to find hidden resources
and spider a web site using fewer requests.
The script works by sending requests for resources like index and home without specifying the extension. If mod_negotiate
is enabled (default Apache configuration), the target would reply with content-location header containing target resource
(such as index.html) and vary header containing "negotiate" depending on the configuration.

Script Arguments
http-apache-negotiation.root
target web site root. Defaults to /.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-apache-negotiation --script-args http-apache-negotiation.root=/root/ <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-apache-negotiation'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-apache-negotiation -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-apache-server-status

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-apache-server-status.nse

User Summary
Attempts to retrieve the server-status page for Apache webservers that have mod_status enabled. If the server-status
page exists and appears to be from mod_status the script will parse useful information such as the system uptime,
Apache version and recent HTTP requests.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-apache-server-status <target>
nmap -sV --script http-apache-server-status <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-apache-server-status'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script http-apache-server-status -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-aspnet-debug

Script types: portrule
Categories: vuln, discovery
Download: http://nmap.org/svn/scripts/http-aspnet-debug.nse

User Summary
Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG request.
The HTTP DEBUG verb is used within ASP.NET applications to start/stop remote debugging sessions.
The script sends a 'stop-debug' command to determine the application's current configuration state but access to RPC services
is required to interact with the debugging session. The request does not change the application debugging configuration.

Script Arguments
http-debug.path
Path to URI. Default: /
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-debug <target>
nmap --script http-debug --script-args http-aspnet-debug.path=/path <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-apache-server-status'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-apache-server-status -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-auth-finder

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-auth-finder.nse

User Summary
Spiders a web site to find web pages requiring form-based or HTTP-based authentication. The results are returned
in a table with each url and the detected method.

Script Arguments
http-auth-finder.url
the url to start spidering. This is a URL relative to the scanned host
http-auth-finder.maxdepth
the maximum amount of directories beneath the initial url to spider.
A negative value disables the limit. (default: 3)
http-auth-finder.maxpagecount
the maximum amount of pages to visit. A negative value disables the limit (default: 20)
http-auth-finder.withinhost
only spider URLs within the same host. (default: true)
http-auth-finder.withindomain
only spider URLs within the same domain. This widens the scope from withinhost and can not be
used in combination. (default: false)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist,
httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 80 --script http-auth-finder <ip>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-auth-finder -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-auth-finder -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-auth

Script types: portrule
Categories: default, auth, safe
Download: http://nmap.org/svn/scripts/http-auth.nse

User Summary
Retrieves the authentication scheme and realm of a web service that requires authentication.

Script Arguments
http-auth.path
Define the request path
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-auth [--script-args http-auth.path=/login] -p80 <host>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-auth -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-auth -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-avaya-ipoffice-users

Script types: portrule
Categories: exploit, vuln
Download: http://nmap.org/svn/scripts/http-avaya-ipoffice-users.nse

User Summary
Attempts to enumerate users in Avaya IP Office systems 7.x.
Avaya IP Office systems allow unauthenticated access to the URI '/system/user/scn_user_list' which returns a XML
file containing user information such as display name, full name and extension number.
Tested on Avaya IP Office 7.0(27).

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -p80 --script http-avaya-ipoffice-users <target>
nmap -sV --script http-avaya-ipoffice-users <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-avaya-ipoffice-users -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-avaya-ipoffice-users -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-awstatstotals-exec

Script types: portrule
Categories: vuln, intrusive, exploit
Download: http://nmap.org/svn/scripts/http-awstatstotals-exec.nse

User Summary
Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to 1.14 and possibly other products
based on it (CVE: 2008-3922).
This vulnerability can be exploited through the GET variable sort. The script queries the web server with the
command payload encoded using PHP's chr() function:
?sort={%24{passthru%28chr(117).chr(110).chr(97).chr(109).chr(101).chr(32).chr(45).chr(97)%29}}{%24{exit%28%29}}

Common paths for Awstats Total:
    /awstats/index.php
    /awstatstotals/index.php
    /awstats/awstatstotals.php

Script Arguments
http-awstatstotals-exec.uri
Awstats Totals URI including path. Default: /index.php
http-awstatstotals-exec.cmd
Command to execute. Default: whoami
http-awstatstotals-exec.outfile
Output file. If set it saves the output in this file.
Other useful args when running this script: http.useragent - User Agent to use in GET request
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script http-awstatstotals-exec.nse --script-args 'http-awstatstotals-exec.cmd="uname -a",
      http-awstatstotals-exec.uri=/awstats/index.php' <target>
nmap -sV --script http-awstatstotals-exec.nse <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV  --script http-awstatstotals-exec'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-awstatstotals-exec -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "10":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-axis2-dir-traversal

User Summary
Exploits a directory traversal vulnerability in Apache Axis2 version 1.4.1 by sending a specially crafted
request to the parameter xsd (OSVDB-59001).
By default it will try to retrieve the configuration file of the  Axis2 service '/conf/axis2.xml' using the
path '/axis2/services/' to return the username and password of the admin account.
To exploit this vulnerability we need to detect a valid service running on the installation so we extract it from /listServices
before exploiting the directory traversal vulnerability.
By default it will retrieve the configuration file, if you wish to retrieve other files you need to set the argument
http-axis2-dir-traversal.file correctly to traverse to the file's directory. Ex. ../../../../../../../../../etc/issue
To check the version of an Apache Axis2 installation go to: http://domain/axis2/services/Version/getVersion

Script Arguments
http-axis2-dir-traversal.file
Remote file to retrieve
http-axis2-dir-traversal.outfile
Output file
http-axis2-dir-traversal.basepath
Basepath to the services page. Default: /axis2/services/
slaxml.debug
See the documentation for the slaxml library.
creds.[service], creds.global
See the documentation for the creds library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80,8080 --script http-axis2-dir-traversal --script-args 'http-axis2-dir-traversal.file=../../../../../../../etc/issue' <host/ip>
nmap -p80 --script http-axis2-dir-traversal <host/ip>

Default Option Used in script:
nmap -p 80,8080 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,8008[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-axis2-dir-traversal -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-axis2-dir-traversal -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "11":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-backup-finder

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-backup-finder.nse

User Summary
Spiders a website and attempts to identify backup copies of discovered files. It does so by requesting a number
of different combinations of the filename (eg. index.bak, index.html~, copy of index.html).

Script Arguments
http-backup-finder.maxpagecount
the maximum amount of pages to visit. A negative value disables the limit (default: 20)
http-backup-finder.withindomain
only spider URLs within the same domain. This widens the scope from withinhost and can not
 be used in combination. (default: false)
http-backup-finder.maxdepth
the maximum amount of directories beneath the initial url to spider.
A negative value disables the limit. (default: 3)
http-backup-finder.url
the url to start spidering. This is a URL relative to the scanned host eg. /default.html (default: /)
http-backup-finder.withinhost
only spider URLs within the same host. (default: true)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url,
httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-backup-finder <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-backup-finder'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-backup-finder -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "12":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-barracuda-dir-traversal

Script types: portrule
Categories: intrusive, exploit, auth
Download: http://nmap.org/svn/scripts/http-barracuda-dir-traversal.nse

User Summary
Attempts to retrieve the configuration settings from a Barracuda Networks Spam & Virus Firewall device using the
directory traversal vulnerability described at http://seclists.org/fulldisclosure/2010/Oct/119.
This vulnerability is in the "locale" parameter of "/cgi-mod/view_help.cgi" or "/cgi-bin/view_help.cgi", allowing
the information to be retrieved from a MySQL database dump. The web administration interface runs on port 8000 by default.

Script Arguments
http-max-cache-size
Set max cache size. The default value is 100,000. Barracuda config files vary in size mostly due to the number of users. Using a max cache size of 5,000,000 bytes should be enough for config files containing up to 5,000 users.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-barracuda-dir-traversal --script-args http-max-cache-size=5000000 -p <port> <host>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-barracuda-dir-traversal'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-barracuda-dir-traversal -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "13":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/http-brute.nse

User Summary
Performs brute force password auditing against http basic, digest and ntlm authentication.
This script uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are
stored in the nmap registry, using the creds library, for other scripts to use.

Script Arguments
http-brute.hostname
sets the host header in case of virtual hosting
http-brute.method
sets the HTTP method to use (default: GET)
http-brute.path
points to the path protected by authentication (default: /)
creds.[service], creds.global
See the documentation for the creds library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly,
brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap --script http-brute -p 80 <host>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "14":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-cakephp-version

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-cakephp-version.nse

User Summary
Obtains the CakePHP version of a web application built with the CakePHP framework by fingerprinting default files
shipped with the CakePHP framework.
This script queries the files 'vendors.php', 'cake.generic.css', 'cake.icon.png' and 'cake.icon.gif' to try to obtain
the version of the CakePHP installation.
Since installations that had been upgraded are prone to false positives due to old files that aren't removed,
the script displays 3 different versions:
    Codebase: Taken from the existence of vendors.php (1.1.x or 1.2.x if it does and 1.3.x otherwise)
    Stylesheet: Taken from cake.generic.css
    Icon: Taken from cake.icon.gif or cake.icon.png
For more information about CakePHP visit: http://www.cakephp.org/.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80,443 --script http-cakephp-version <host/ip>

Default Option Used in script:
nmap -p 80,443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-cakephp-version -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-cakephp-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "15":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-chrono

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-chrono.nse

User Summary
Measures the time a website takes to deliver a web page and returns the maximum, minimum and average time
it took to fetch a page.
Web pages that take longer time to load could be abused by attackers in DoS or DDoS attacks due to the fact
that they are likely to consume more resources on the target server. This script could help identifying these web pages.

Script Arguments
http-chrono.tries
the number of times to fetch a page based on which max, min and average calculations are performed.
http-chrono.withindomain
only spider URLs within the same domain. This widens the scope from withinhost and can not
 be used in combination. (default: false)
http-chrono.withinhost
only spider URLs within the same host. (default: true)
http-chrono.maxdepth
the maximum amount of directories beneath the initial url to spider.
A negative value disables the limit. (default: 3)
http-chrono.maxpagecount
the maximum amount of pages to visit. A negative value disables the limit (default: 1)
http-chrono.url
the url to start spidering. This is a URL relative to the scanned host eg. /default.html (default: /)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist,
httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-chrono <ip>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-chrono'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-chrono -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)   
    elif option == "16":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-cisco-anyconnect

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-cisco-anyconnect.nse

User Summary
Connect as Cisco AnyConnect client to a Cisco SSL VPN and retrieves version and tunnel information.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
anyconnect.group, anyconnect.mac, anyconnect.ua, anyconnect.version
See the documentation for the anyconnect library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 443 --script http-cisco-anyconnect <target>

Default Option Used in script:
nmap -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-cisco-anyconnect -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-cisco-anyconnect -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "17":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-coldfusion-subzero

Script types: portrule
Categories: exploit
Download: http://nmap.org/svn/scripts/http-coldfusion-subzero.nse

User Summary
Attempts to retrieve version, absolute path of administration panel and the file 'password.properties' from vulnerable
installations of ColdFusion 9 and 10.
This was based on the exploit 'ColdSub-Zero.pyFusion v2'.

Script Arguments
http-coldfusion-subzero.basepath
Base path. Default: /.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script http-coldfusion-subzero <target>
nmap -p80 --script http-coldfusion-subzero --script-args basepath=/cf/ <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-coldfusion-subzero -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-coldfusion-subzero -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "18":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-comments-displayer

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-comments-displayer.nse

User Summary
Extracts and outputs HTML and JavaScript comments from HTTP responses.

Script Arguments
http-comments-displayer.singlepages
Some single pages to check for comments. For example, {"/", "/wiki"}. Default: nil (crawler mode on)
http-comments-displayer.context
declares the number of chars to extend our final strings. This is useful when we need to to see the code that the comments
are referring to. Default: 0, Maximum Value: 50
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,
httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-comments-displayer.nse <host>
This scripts uses patterns to extract HTML comments from HTTP
responses and writes these to the command line.

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-comments-displayer -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-comments-displayer -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "19":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-config-backup

Script types: portrule
Categories: auth, intrusive
Download: http://nmap.org/svn/scripts/http-config-backup.nse

User Summary
Checks for backups and swap files of common content management system and web server configuration files.
When web server files are edited in place, the text editor can leave backup or swap files in a place
where the web server can serve them. The script checks for these files:
    wp-config.php: WordPress
    config.php: phpBB, ExpressionEngine
    configuration.php: Joomla
    LocalSettings.php: MediaWiki
    /mediawiki/LocalSettings.php: MediaWiki
    mt-config.cgi: Movable Type
    mt-static/mt-config.cgi: Movable Type
    settings.php: Drupal
    .htaccess: Apache
And for each of these file applies the following transformations (using config.php as an example):
    config.bak: Generic backup.
    config.php.bak: Generic backup.
    config.php~: Vim, Gedit.
    #config.php#: Emacs.
    config copy.php: Mac OS copy.
    Copy of config.php: Windows copy.
    config.php.save: GNU Nano.
    .config.php.swp: Vim swap.
    config.php.swp: Vim swap.
    config.php.old: Generic backup.

Script Arguments
http-config-backup.save
directory to save all the valid config files found
http-config-backup.path
the path where the CMS is installed
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-config-backup <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-config-backup'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-config-backup -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "20":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-cors

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-cors.nse

User Summary
Tests an http server for Cross-Origin Resource Sharing (CORS), a way for domains to explicitly opt
in to having certain methods invoked by another domain.
The script works by setting the Access-Control-Request-Method header field for certain enumerated methods in
OPTIONS requests, and checking the responses.

Script Arguments
http-cors.path
The path to request. Defaults to /.
http-cors.origin
The origin used with requests. Defaults to example.com.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 80 --script http-cors <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-cors  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-cors  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "21":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-cross-domain-policy

Script types: portrule
Categories: safe, external, vuln
Download: http://nmap.org/svn/scripts/http-cross-domain-policy.nse

User Summary
Checks the cross-domain policy file (/crossdomain.xml) and the client-acces-policy file (/clientaccesspolicy.xml)
in web applications and lists the trusted domains. Overly permissive settings enable Cross Site Request Forgery
attacks and may allow attackers to access sensitive data.
This script is useful to detect permissive configurations and possible domain names available for purchase to exploit
the application.
The script queries instantdomainsearch.com to lookup the domains. This functionality is turned off by default,
to enable it set the script argument http-crossdomainxml.domain-lookup.

Script Arguments
http-crossdomainxml.domain-lookup
Boolean to check domain availability. Default:false
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script http-crossdomainxml <target>
nmap -p 80 --script http-crossdomainxml --script-args http.domain-lookup=true <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-crossdomainxml'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-crossdomainxml -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "22":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-csrf

Script types: portrule
Categories: intrusive, exploit, vuln
Download: http://nmap.org/svn/scripts/http-csrf.nse

User Summary
This script detects Cross Site Request Forgeries (CSRF) vulnerabilities.
It will try to detect them by checking each form if it contains an unpredictable token for each user.
Without one an attacker may forge malicious requests.
To recognize a token in a form, the script will iterate through the form's attributes and will search for
common patterns in their names.If that fails, it will also calculate the entropy of each attribute's value.
A big entropy means a possible token.
A common use case for this script comes along with a cookie that gives access in pages that require authentication,
because that's where the privileged exist. See the http library's documentation to set your own cookie.

Script Arguments
http-csrf.singlepages
The pages that contain the forms to check. For example, {/upload.php, /login.php}.
Default: nil (crawler mode on)
http-csrf.checkentropy
If this is set the script will also calculate the entropy of the field's value to determine
if it is a token, rather than just checking its name. Default: true
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist,
httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-csrf.nse <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-csrf  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-csrf -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "23":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-date

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-date.nse

User Summary
Gets the date from HTTP-like services. Also prints how much the date differs from local time.
Local time is the time the HTTP request was sent, so the difference includes at least the duration of one RTT.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script=http-date <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-date'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-date -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "24":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-default-accounts

Script types: portrule
Categories: discovery, auth, intrusive
Download: http://nmap.org/svn/scripts/http-default-accounts.nse

User Summary
Tests for access with default credentials used by a variety of web applications and devices.
It works similar to http-enum, we detect applications by matching known paths and launching a login routine using
default credentials when found. This script depends on a fingerprint file containing the target's information: name, category, l
ocation paths, default credentials and login routine.

You may select a category if you wish to reduce the number of requests. We have categories like:
    web - Web applications
    routers - Routers
    security - CCTVs and other security devices
    industrial - Industrial systems
    printer - Network-attached printers and printer servers
    storage - Storage devices
    virtualization - Virtualization systems
    console - Remote consoles

Script Arguments
http-default-accounts.category
Selects a category of fingerprints to use.
http-default-accounts.fingerprintfile
Fingerprint filename. Default: http-default-accounts-fingerprints.lua
http-default-accounts.basepath
Base path to append to requests. Default: "/"
slaxml.debug
See the documentation for the slaxml library.
creds.[service], creds.global
See the documentation for the creds library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-default-accounts host/ip

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-default-accounts  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-default-accounts -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "25":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-devframework

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-devframework.nse

User Summary
Tries to find out the technology behind the target website.
The script checks for certain defaults that might not have been changed, like common headers or URLs or HTML content.
While the script does some guessing, note that overall there's no way to determine what technologies a given site is using.
You can help improve this script by adding new entries to nselib/data/http-devframework-fingerprints.lua
Each entry must have:
    rapidDetect - Callback function that is called in the beginningof detection process. It takes the host and port of target
    website as arguments.
    consumingDetect - Callback function that is called for each spidered page. It takes the body of the response (HTML code) and
    the requested path as arguments.

Script Arguments
http-errors.rapid
boolean value that determines if a rapid detection should take place.
The main difference of a rapid vs a lengthy detection is that
second one requires crawling through the website.
Default: false (lengthy detection is performed)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount,
httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,
httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-devframework.nse <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-devframework  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-devframework -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "26":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-dlink-backdoor

Script types: portrule
Categories: exploit, vuln
Download: http://nmap.org/svn/scripts/http-dlink-backdoor.nse

User Summary
Detects a firmware backdoor on some D-Link routers by changing the User-Agent to a "secret" value.
Using the "secret" User-Agent bypasses authentication and allows admin access to the router.
The following router models are likely to be vulnerable: DIR-100, DIR-120, DI-624S, DI-524UP,
DI-604S, DI-604UP, DI-604+, TM-G5240
In addition, several Planex routers also appear to use the same firmware: BRL-04UR, BRL-04CW
Reference: http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script http-dlink-backdoor <target>

Default Option Used in script:
nmap -sv --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-dlink-backdoor'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-dlink-backdoor -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "27":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-dombased-xss

Script types: portrule
Categories: intrusive, exploit, vuln
Download: http://nmap.org/svn/scripts/http-dombased-xss.nse

User Summary
It looks for places where attacker-controlled information in the DOM may be used to affect JavaScript
execution in certain ways. The attack is explained here: http://www.webappsec.org/projects/articles/071105.shtml

Script Arguments
http-dombased-xss.singlepages
The pages to test. For example, {/index.php, /profile.php}. Default: nil (crawler mode on)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist,
httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-dombased-xss.nse <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-dombased-xss  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-dombased-xss -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "28":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-domino-enum-passwords

Script types: portrule
Categories: intrusive, auth
Download: http://nmap.org/svn/scripts/http-domino-enum-passwords.nse

User Summary
Attempts to enumerate the hashed Domino Internet Passwords that are (by default) accessible by all
authenticated users. This script can also download any Domino ID Files attached to the Person document.

Script Arguments
domino-enum-passwords.hostname
sets the host header in case of virtual hosting
domino-enum-passwords.password
Password for HTTP auth, if required
domino-enum-passwords.count
the number of internet hashes and id files to fetch. If a negative value is given,
all hashes and id files are retrieved (default: 10)
domino-enum-passwords.path
points to the path protected by authentication
domino-enum-passwords.username
Username for HTTP auth, if required
domino-enum-passwords.idpath
the path where downloaded ID files should be saved If not given, the script will
only indicate if the ID file is donwloadable or not
slaxml.debug
See the documentation for the slaxml library.
creds.[service], creds.global
See the documentation for the creds library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script domino-enum-passwords -p 80 <host> --script-args domino-enum-passwords.username='patrik karlsson',domino-enum-passwords.password=secret

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script domino-enum-passwords  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script domino-enum-passwords -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "29":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-drupal-enum-users

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-drupal-enum-users.nse

User Summary
Enumerates Drupal users by exploiting an information disclosure vulnerability in Views, Drupal's most popular module.
Requests to admin/views/ajax/autocomplete/user/STRING return all usernames that begin with STRING. The script works by
iterating STRING over letters to extract all usernames.

Script Arguments
http-drupal-enum-users.root
base path. Defaults to "/"
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-drupal-enum-users --script-args http-drupal-enum-users.root="/path/" <targets>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-drupal-enum-users'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-drupal-enum-users -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "30":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-drupal-enum

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-drupal-enum.nse

User Summary
Enumerates the installed Drupal modules/themes by using a list of known modules and themes.
The script works by iterating over module/theme names and requesting MODULE_PATH/MODULE_NAME/LICENSE.txt for modules
and THEME_PATH/THEME_NAME/LICENSE.txt. MODULE_PATH/THEME_PATH which is either provided by the user, grepped for in
the html body or defaulting to sites/all/modules/.

Script Arguments
http-drupal-enum.themes_path
Direct Path for Themes
http-drupal-enum.number
Number of modules to check. Use this option with a number or "all" as an argument to test for all modules. Defaults to 100.
http-drupal-enum.type
default all.choose between "themes" and "modules"
http-drupal-enum.root
The base path. Defaults to /.
http-drupal-enum.modules_path
Direct Path for Modules
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 80 --script http-drupal-enum <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-drupal-enum  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-drupal-enum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "31":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-enum

Script types: portrule
Categories: discovery, intrusive, vuln
Download: http://nmap.org/svn/scripts/http-enum.nse

User Summary
Enumerates directories used by popular web applications and servers.
This parses a fingerprint file that's similar in format to the Nikto Web application scanner. This script, however,
takes it one step further by building in advanced pattern matching as well as having the ability to identify specific
versions of Web applications.

Script Arguments
http-enum.basepath
The base path to prepend to each request. Leading/trailing slashes are ignored.
http-fingerprints.nikto-db-path
Looks at the given path for nikto database. It then converts the records in nikto's database
into our Lua table format and adds them to our current fingerprints if they don't exist already.
Set this argument to display all status codes that may indicate a valid page, not just 200 OK and
401 Authentication Required pages. Although this is more likely to find certain hidden folders,
it also generates far more false positives.
http-enum.category
Set to a category (as defined in the fingerprints file). Some options are 'attacks', 'database',
'general', 'microsoft', 'printer', etc.
http-enum.fingerprintfile
Specify a different file to read fingerprints from.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script=http-enum <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-enum'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-enum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)        
    elif option == "32":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-errors

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-errors.nse

User Summary
This script crawls through the website and returns any error pages.
The script will return all pages (sorted by error code) that respond with an http code equal or above 400.
To change this behaviour, please use the errcodes option.
The script, by default, spiders and searches within forty pages. For large web applications make sure to
increase httpspider's maxpagecount value. Please, note that the script will become more intrusive though.

Script Arguments
http-errors.errcodes
The error codes we are interested in. Default: nil (all codes >= 400)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url,
httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-errors.nse <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-errors  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-errors -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "33":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-exif-spider

Script types: portrule
Categories: intrusive
Download: http://nmap.org/svn/scripts/http-exif-spider.nse

User Summary
Spiders a site's images looking for interesting exif data embedded in .jpg files. Displays the make and
model of the camera, the date the photo was taken, and the embedded geotag information.

Script Arguments
http-exif-spider.url
the url to start spidering. This is a URL relative to the scanned host eg. /default.html (default: /)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-exif-spider -p80,443 <host>

Default Option Used in script:
nmap -p 80,443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-exif-spider  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-exif-spider -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "34":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-favicon

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-favicon.nse

User Summary
Gets the favicon ("favorites icon") from a web page and matches it against a database of the icons
of known web applications. If there is a match, the name of the application is printed; otherwise the
MD5 hash of the icon data is printed.
If the script argument favicon.uri is given, that relative URI is always used to find the favicon.
Otherwise, first the page at the root of the web server is retrieved and parsed for a <link rel="icon"> element.
If that fails, the icon is looked for in /favicon.ico. If a <link> favicon points to a different host or port, it is ignored.

Script Arguments
favicon.root
Web server path to search for favicon.
favicon.uri
URI that will be requested for favicon.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-favicon.nse \
   --script-args favicon.root=<root>,favicon.uri=<uri>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-favicon'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-favicon -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "35":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-feed

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-feed.nse

User Summary
This script crawls through the website to find any rss or atom feeds.
The script, by default, spiders and searches within forty pages. For large web applications make sure to
increase httpspider's maxpagecount value. Please, note that the script will become more intrusive though.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist,
httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-feed.nse <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-feed  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-feed -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "36":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-fetch

Script types: portrule
Categories: safe
Download: http://nmap.org/svn/scripts/http-fetch.nse

User Summary
The script is used to fetch files from servers.
The script supports three different use cases :
    The paths argument isn't provided, the script spiders the host and downloads files in their respective folders relative
    to the one provided using "destination".
    The paths argument(a single item or list) is provided and the path starts with "/", the script tries to fetch the path
    relative to the url provided via the argument "url".
    The paths argument(a single item or list) is provided and the path doesn't start with "/". Then the script spiders the
    host and tries to find files which contain the path(now treated as a pattern).

Script Arguments
http-fetch.withinhost
The default behavior is to fetch files from the same host. Set to False to do otherwise.
http-fetch.destination
- The full path of the directory to save the file(s) to preferably with the trailing slash.
http-fetch.maxpagecount
The maximum amount of pages to fetch.
http-fetch.maxdepth
The maximum amount of directories beneath the initial url to spider. A negative value disables the limit. (default: 3)
http-fetch.files
- The name of the file(s) to be fetched.
http-fetch.paths
A list of paths to fetch. If relative, then the site will be spidered to find matching filenames. Otherwise,
they will be fetched relative to the url script-arg.
http-fetch.url
The base URL to start fetching. Default: "/"
http-fetch.withindomain
If set to true then the crawling would be restricted to the domain provided by the user.
http-fetch.noblacklist
By default files like jpg, rar, png are blocked. To fetch such files set noblacklist to true.

Example Usage
nmap --script http-fetch --script-args destination=/tmp/mirror <target>
nmap --script http-fetch --script-args 'paths={/robots.txt,/favicon.ico}' <target>
nmap --script http-fetch --script-args 'paths=.html' <target>
nmap --script http-fetch --script-args 'url=/images,paths={.jpg,.png,.gif}' <target>
Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-fetch'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-fetch -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "37":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-fileupload-exploiter

Script types: portrule
Categories: intrusive, exploit, vuln
Download: http://nmap.org/svn/scripts/http-fileupload-exploiter.nse

User Summary
Exploits insecure file upload forms in web applications using various techniques like changing the Content-type header
or creating valid image files containing the payload in the comment.

Script Arguments
http-fileupload-exploiter.fieldvalues
The script will try to fill every field found in the upload form but that may fail due to fields' restrictions.
You can manually fill those fields using this table. For example, {gender = "male", email = "foo@bar.com"}. Default: {}
http-fileupload-exploiter.formpaths
The pages that contain the forms to exploit. For example, {/upload.php, /login.php}.
Default: nil (crawler mode on)
http-fileupload-exploiter.uploadspaths
Directories with the uploaded files. For example, {/avatars, /photos}.
Default: {'/uploads', '/upload', '/file', '/files', '/downloads'}
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist,
 httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-fileupload-exploiter.nse <target>

This script discovers the upload form on the target's page and
attempts to exploit it using 3 different methods:

1) At first, it tries to upload payloads with different insecure
extensions. This will work against a weak blacklist used by a file
name extension verifier.

2) If (1) doesn't work, it will try to upload the same payloads
this time with different Content-type headers, like "image/gif"
instead of the "text/plain". This will trick any mechanisms that
check the MIME type.

3) If (2), doesn't work, it will create some proper GIF images
that contain the payloads in the comment. The interpreter will
see the executable inside some binary garbage. This will bypass
any check of the actual content of the uploaded file.

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-fileupload-exploiter  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-fileupload-exploiter -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "38":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-form-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/http-form-brute.nse

User Summary
Performs brute force password auditing against http form-based authentication.
This script uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are stored in
the nmap registry, using the creds library, for other scripts to use.
The script automatically attempts to discover the form method, action, and field names to use in order to perform password
guessing. (Use argument path to specify the page where the form resides.) If it fails doing so the form components can be s
upplied using arguments method, path, uservar, and passvar. The same arguments can be used to selectively override the detection
outcome.

Script Arguments
http-form-brute.hostname
sets the host header in case of virtual hosting
http-form-brute.path
identifies the page that contains the form (default: "/"). The script analyses the content of this page
to determine the form destination, method, and fields. If argument passvar is specified then the form detection
is not performed and the path argument is instead used as the form submission destination (the form action).
 Use the other arguments to define the rest of the form manually as necessary.
http-form-brute.onfailure
(optional) sets the message/pattern to expect on unsuccessful authentication
http-form-brute.sessioncookies
Attempt to grab session cookies before submitting the form. Setting this to "false" could
speed up cracking against forms that do not require any cookies to be set before logging in. Default: true
http-form-brute.passvar
sets the http-variable name that holds the password used to authenticate. If this argument
is set then the form detection is not performed. Use the other arguments to define the form manually.
http-form-brute.onsuccess
(optional) sets the message/pattern to expect on successful authentication
http-form-brute.uservar
(optional) sets the form field name that holds the username used to authenticate.
http-form-brute.method
sets the HTTP method (default: "POST")
creds.[service], creds.global
See the documentation for the creds library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode,
brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap --script http-form-brute -p 80 <host>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-form-brute  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-form-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "39":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-form-fuzzer

Script types: portrule
Categories: fuzzer, intrusive
Download: http://nmap.org/svn/scripts/http-form-fuzzer.nse

User Summary
Performs a simple form fuzzing against forms found on websites. Tries strings and numbers of increasing length and
attempts to determine if the fuzzing was successful.

Script Arguments
http-form-fuzzer.minlength
the minimum length of a string that will be used for fuzzing, defaults to 300000
http-form-fuzzer.maxlength
the maximum length of a string that will be used for fuzzing, defaults to 310000
http-form-fuzzer.targets
a table with the targets of fuzzing, for example {{path = /index.html, minlength = 40002}, {path = /foo.html, maxlength = 10000}}.
The path parameter is required, if minlength or maxlength is not specified, then the values of http-form-fuzzer.minlength or http-form-fuzzer.maxlength
will be used. Defaults to {{path="/"}}
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist,
httpspider.url, httpspider.useheadfornonwebfiles,
httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-form-fuzzer --script-args 'http-form-fuzzer.targets={1={path=/},2={path=/register.html}}' -p 80 <host>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-form-fuzzer  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-form-fuzzer -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "40":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-frontpage-login

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/http-frontpage-login.nse

User Summary
Checks whether target machines are vulnerable to anonymous Frontpage login.
Older, default configurations of Frontpage extensions allow remote user to login anonymously which may lead to server compromise.

Script Arguments
http-frontpage-login.path
Path prefix to Frontpage directories. Defaults to root ("/").
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap <target> -p 80 --script=http-frontpage-login


Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-frontpage-login  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-frontpage-login -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "41":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-generator

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-generator.nse

User Summary
Displays the contents of the "generator" meta tag of a web page (default: /) if there is one.

Script Arguments
http-generator.path
Specify the path you want to check for a generator meta tag (default to '/').
http-generator.redirects
Specify the maximum number of redirects to follow (defaults to 3).
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-generator [--script-args http-generator.path=<path>,http-generator.redirects=<number>,...] <host>


Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-generator'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-generator -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "42":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-git

Script types: portrule
Categories: default, safe, vuln
Download: http://nmap.org/svn/scripts/http-git.nse

User Summary
Checks for a Git repository found in a website's document root /.git/<something>) and retrieves as much repo information as possible, including language/framework, remotes, last commit message, and repository description.

Script Arguments
http-git.root
URL path to search for a .git directory. Default: /
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV -sC <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-git'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-git -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "43":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-gitweb-projects-enum

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-gitweb-projects-enum.nse

User Summary
Retrieves a list of Git projects, owners and descriptions from a gitweb (web interface to the Git revision control system).
Script Arguments
http-gitweb.projects-enum.path
specifies the location of gitweb (default: /)
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 www.example.com --script http-gitweb-projects-enum


Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-gitweb-projects-enum  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-gitweb-projects-enum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "44":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-google-malware

Script types: portrule
Categories: malware, discovery, safe, external
Download: http://nmap.org/svn/scripts/http-google-malware.nse

User Summary
Checks if hosts are on Google's blacklist of suspected malware and phishing servers. These lists are constantly
updated and are part of Google's Safe Browsing service.
To do this the script queries the Google's Safe Browsing service and you need to have your own API key to access
Google's Safe Browsing Lookup services. Sign up for yours at http://code.google.com/apis/safebrowsing/key_signup.html

Script Arguments
http-google-malware.url
URL to check. Default: http/https://host
http-google-malware.api
API key for Google's Safe Browsing Lookup service
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-google-malware <host>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-google-malware  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-google-malware -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "45":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-grep

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-grep.nse

User Summary
Spiders a website and attempts to match all pages and urls against a given string. Matches are counted and grouped per url
under which they were discovered.
Features built in patterns like email, ip, ssn, discover, amex and more. The script searches for email and ip by default.

Script Arguments
http.breakonmatch
Returns output if there is a match for a single pattern type.
http-grep.builtins
supply a single or a list of built in types. supports email, phone, mastercard, discover, visa, amex, ssn and ip addresses.
If you just put in script-args http-grep.builtins then all will be enabled.
http-grep.maxdepth
the maximum amount of directories beneath the initial url to spider. A negative value disables the limit. (default: 3)
http-grep.withinhost
only spider URLs within the same host. (default: true)
http-grep.withindomain
only spider URLs within the same domain. This widens the scope from withinhost and can not be used in combination. (default: false)
http-grep.match
the string to match in urls and page contents or list of patterns separated by delimiter
http-grep.maxpagecount
the maximum amount of pages to visit. A negative value disables the limit (default: 20)
http-grep.url
the url to start spidering. This is a URL relative to the scanned host eg. /default.html (default: /)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist,
httpspider.url, httpspider.useheadfornonwebfiles,
httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 80 www.example.com --script http-grep --script-args='match="[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?",breakonmatch'
nmap -p 80 www.example.com --script http-grep --script-args 'http-grep.builtins ={"mastercard", "discover"}, http-grep.url="example.html"'

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-grep  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-grep -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "46":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-headers

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-headers.nse

User Summary
Performs a HEAD request for the root folder ("/") of a web server and displays the HTTP headers returned.

Script Arguments
useget
Set to force GET requests instead of HEAD.
path
The path to request, such as /index.php. Default /.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script=http-headers <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-headers'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-headers -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "47":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-huawei-hg5xx-vuln

Script types: portrule
Categories: exploit, vuln
Download: http://nmap.org/svn/scripts/http-huawei-hg5xx-vuln.nse

User Summary
Detects Huawei modems models HG530x, HG520x, HG510x (and possibly others...) vulnerable to a remote credential
and information disclosure vulnerability. It also extracts the PPPoE credentials and other interesting configuration values.
Attackers can query the URIs "/Listadeparametros.html" and "/wanfun.js" to extract sensitive information including
PPPoE credentials, firmware version, model, gateway, dns servers and active connections among other values.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
    nmap -p80 --script http-huawei-hg5xx-vuln <target>
    nmap -sV http-huawei-hg5xx-vuln <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-huawei-hg5xx-vuln  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-huawei-hg5xx-vuln -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "48":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-icloud-findmyiphone

Script types: prerule
Categories: discovery, safe, external
Download: http://nmap.org/svn/scripts/http-icloud-findmyiphone.nse

User Summary
Retrieves the locations of all "Find my iPhone" enabled iOS devices by querying the MobileMe web service (
authentication required).

Script Arguments
http-icloud-findmyiphone.username
the Apple Id username
http-icloud-findmyiphone.password
the Apple Id password
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -sn -Pn --script http-icloud-findmyiphone --script-args='username=<user>,password=<pass>'

Default Option Used in script:
nmap -sn -Pn --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn -Pn --script http-icloud-findmyiphone'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-icloud-findmyiphone -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "49":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-icloud-sendmsg

Script types: prerule
Categories: discovery, safe, external
Download: http://nmap.org/svn/scripts/http-icloud-sendmsg.nse

User Summary
Sends a message to a iOS device through the Apple MobileMe web service. The device has to be registered
 with an Apple ID using the Find My Iphone application.

Script Arguments
http-icloud-sendmsg.username
the Apple ID username
http-icloud-sendmsg.sound
boolean specifying if a loud sound should be played while displaying the message. (default: true)
http-icloud-sendmsg.subject
the subject of the message to send to the device.
http-icloud-sendmsg.message
the body of the message to send to the device.
http-icloud-sendmsg.deviceindex
the device index to which the message should be sent (@see http-icloud-sendmsg.listdevices)
http-icloud-sendmsg.password
the Apple ID password
http-icloud-sendmsg.listdevices
list the devices managed by the specified Apple ID.
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -sn -Pn --script http-icloud-sendmsg --script-args="username=<user>,password=<pass>,http-icloud-sendmsg.listdevices"
nmap -sn -Pn --script http-icloud-sendmsg --script-args="username=<user>,password=<pass>,deviceindex=1,subject='subject',message='hello world.',sound=false"<pass>'

Default Option Used in script:
nmap -sn -Pn --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn -Pn --script http-icloud-sendmsg '+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-icloud-sendmsg  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "50":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-iis-short-name-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/http-iis-short-name-brute.nse

User Summary
Attempts to brute force the 8.3 filenames (commonly known as short names) of files and directories in the root
folder of vulnerable IIS servers. This script is an implementation of the PoC "iis shortname scanner".
The script uses ~,? and * to bruteforce the short name of files present in the IIS document root. Short names h
ave a restriction of 6 character file name followed by a three character extension.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -p80 --script http-iis-short-name-brute <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-iis-short-name-brute  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-iis-short-name-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "51":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-iis-webdav-vuln

Script types: portrule
Categories: vuln, intrusive
Download: http://nmap.org/svn/scripts/http-iis-webdav-vuln.nse

User Summary
Checks for a vulnerability in IIS 5.1/6.0 that allows arbitrary users to access secured WebDAV folders by
searching for a password-protected folder and attempting to access it. This vulnerability was patched in Microsoft
Security Bulletin MS09-020, https://nmap.org/r/ms09-020.
A list of well known folders (almost 900) is used by default. Each one is checked, and if returns an authentication
request (401), another attempt is tried with the malicious encoding. If that attempt returns a successful result (207),
then the folder is marked as vulnerable.

Script Arguments
basefolder
The folder to start in; eg, "/web" will try "/web/xxx".
folderdb
The filename of an alternate list of folders.
webdavfolder
Selects a single folder to use, instead of using a built-in list.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-iis-webdav-vuln -p80,8080 <host>

Default Option Used in script:
nmap -p 80,8080 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,8080[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-iis-webdav-vuln -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-iis-webdav-vuln -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "52":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-internal-ip-disclosure

Script types: portrule
Categories: vuln, discovery, safe
Download: http://nmap.org/svn/scripts/http-internal-ip-disclosure.nse

User Summary
Determines if the web server leaks its internal IP address when sending an HTTP/1.0 request without a Host header.
Some misconfigured web servers leak their internal IP address in the response headers when returning a redirect
response. This is a known issue for some versions of Microsoft IIS, but affects other web servers as well.

Script Arguments
http-internal-ip-disclosure.path
Path to URI. Default: /
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
    nmap --script http-internal-ip-disclosure <target>
    nmap --script http-internal-ip-disclosure --script-args http-internal-ip-disclosure.path=/path <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-internal-ip-disclosure '+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-internal-ip-disclosure  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "53":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-iis-webdav-vuln

Script types: portrule
Categories: vuln, intrusive
Download: http://nmap.org/svn/scripts/http-iis-webdav-vuln.nse

User Summary
Checks for a vulnerability in IIS 5.1/6.0 that allows arbitrary users to access secured WebDAV folders by
searching for a password-protected folder and attempting to access it. This vulnerability was patched in
Microsoft Security Bulletin MS09-020, https://nmap.org/r/ms09-020.
A list of well known folders (almost 900) is used by default. Each one is checked, and if returns an
authentication request (401), another attempt is tried with the malicious encoding. If that attempt returns
a successful result (207), then the folder is marked as vulnerable.
This script is based on the Metasploit auxiliary module auxiliary/scanner/http/wmap_dir_webdav_unicode_bypass

Script Arguments
basefolder
The folder to start in; eg, "/web" will try "/web/xxx".
folderdb
The filename of an alternate list of folders.
webdavfolder
Selects a single folder to use, instead of using a built-in list.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-iis-webdav-vuln -p80,8080 <host>

Default Option Used in script:
nmap -p 80,8080 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,8080[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-iis-webdav-vuln -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-iis-webdav-vuln -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "54":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-litespeed-sourcecode-download

Script types: portrule
Categories: vuln, intrusive, exploit
Download: http://nmap.org/svn/scripts/http-litespeed-sourcecode-download.nse

User Summary
Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x before 4.0.15 to retrieve the
target script's source code by sending a HTTP request with a null byte followed by a .txt file extension (CVE-2010-2333).
If the server is not vulnerable it returns an error 400. If index.php is not found, you may try /phpinfo.php which is
also shipped with LiteSpeed Web Server. The attack payload looks like this:  /index.php\00.txt

Script Arguments
http-litespeed-sourcecode-download.uri
URI path to remote file
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-litespeed-sourcecode-download --script-args http-litespeed-sourcecode-download.uri=/phpinfo.php <host>
nmap -p8088 --script http-litespeed-sourcecode-download <host>

Default Option Used in script:
nmap -p 80,8080 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,8080[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-litespeed-sourcecode-download -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-litespeed-sourcecode-download -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)    
    elif option == "55":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-ls

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-ls.nse

User Summary
Shows the content of an "index" Web page.
TODO: - add support for more page formats

Script Arguments
http-ls.url
base URL path to use (default: /)
http-ls.checksum
compute a checksum for each listed file. Requires OpenSSL. (default: false)
slaxml.debug
See the documentation for the slaxml library.
ls.checksum, ls.empty, ls.errors, ls.human, ls.maxdepth, ls.maxfiles
See the documentation for the ls library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -n -p 80 --script http-ls test-debit.free.fr

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-ls  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-ls  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "56":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-majordomo2-dir-traversal

Script types: portrule
Categories: intrusive, vuln, exploit
Download: http://nmap.org/svn/scripts/http-majordomo2-dir-traversal.nse

User Summary
Exploits a directory traversal vulnerability existing in Majordomo2 to retrieve remote files. (CVE-2011-0049).
Vulnerability originally discovered by Michael Brooks.

Script Arguments
http-majordomo2-dir-traversal.rfile
Remote file to download. Default: /etc/passwd
http-majordomo2-dir-traversal.uri
URI Path to mj_wwwusr. Default: /cgi-bin/mj_wwwusr
http-majordomo2-dir-traversal.outfile
If set it saves the remote file to this location.
Other arguments you might want to use with this script:
    http.useragent - Sets user agent
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-majordomo2-dir-traversal <host/ip>


Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-majordomo2-dir-traversal -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-majordomo2-dir-traversal -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)    
    elif option == "57":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-malware-host

Script types: portrule
Categories: malware, safe
Download: http://nmap.org/svn/scripts/http-malware-host.nse

User Summary
Looks for signature of known server compromises.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script=http-malware-host <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-malware-host'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-malware-host -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "58":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-mcmp

Script types: portrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/http-mcmp.nse

User Summary
Checks if the webserver allows mod_cluster management protocol (MCMP) methods.
The script sends a MCMP PING message to determine protocol support, then issues the DUMP command to
dump the current configuration seen by mod_cluster_manager.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script=http-mcmp <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-mcmp'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-mcmp -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "59":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-method-tamper

Script types: portrule
Categories: auth, vuln
Download: http://nmap.org/svn/scripts/http-method-tamper.nse

User Summary
Attempts to bypass password protected resources (HTTP 401 status) by performing HTTP verb tampering. If an array of
paths to check is not set, it will crawl the web server and perform the check against any password protected resource that it finds.
The script determines if the protected URI is vulnerable by performing HTTP verb tampering and monitoring the status codes.
First, it uses a HEAD request, then a POST request and finally a random generated string ( This last one is useful when web servers
treat unknown request methods as a GET request. This is the case for PHP servers ).
If the table paths is set, it will attempt to access the given URIs. Otherwise, a web crawler is initiated to try to find protected
resources. Note that in a PHP environment with .htaccess files you need to specify a path to a file rather than a directory to find
misconfigured .htaccess files.

Script Arguments
http-method-tamper.timeout
Web crawler timeout. Default: 10s
http-method-tamper.uri
Base URI to crawl. Not applicable if http-method-tamper.paths is set.
http-method-tamper.paths
Array of paths to check. If not set, the script will crawl the web server.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist,
httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
vulns.showall
See the documentation for the vulns library.
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
    nmap -sV --script http-method-tamper <target>
    nmap -p80 --script http-method-tamper --script-args 'http-method-tamper.paths={/protected/db.php,/protected/index.php}' <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-method-tamper -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-method-tamper -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "60":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-method-tamper

Script types: portrule
Categories: auth, vuln
Download: http://nmap.org/svn/scripts/http-method-tamper.nse

User Summary
Attempts to bypass password protected resources (HTTP 401 status) by performing HTTP verb tampering. If an array of
paths to check is not set, it will crawl the web server and perform the check against any password protected resource that it finds.
The script determines if the protected URI is vulnerable by performing HTTP verb tampering and monitoring the status codes.
First, it uses a HEAD request, then a POST request and finally a random generated string ( This last one is useful when web servers
treat unknown request methods as a GET request. This is the case for PHP servers ).
If the table paths is set, it will attempt to access the given URIs. Otherwise, a web crawler is initiated to try to find protected
resources. Note that in a PHP environment with .htaccess files you need to specify a path to a file rather than a directory to find
misconfigured .htaccess files.

Script Arguments
http-method-tamper.timeout
Web crawler timeout. Default: 10s
http-method-tamper.uri
Base URI to crawl. Not applicable if http-method-tamper.paths is set.
http-method-tamper.paths
Array of paths to check. If not set, the script will crawl the web server.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
vulns.showall
See the documentation for the vulns library.
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
    nmap -sV --script http-method-tamper <target>
    nmap -p80 --script http-method-tamper --script-args 'http-method-tamper.paths={/protected/db.php,/protected/index.php}' <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-method-tamper -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-method-tamper -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "61":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-mobileversion-checker

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-mobileversion-checker.nse

User Summary
Checks if the website holds a mobile version.

Script Arguments
newtargets

If this is set, add any newly discovered hosts to nmap scanning queue. Default: nil
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url,
httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
max-newtargets
See the documentation for the target library.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -p80 --script http-mobileversion-checker.nse <host>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script  http-mobileversion-checker -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-mobileversion-checker -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "62":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-ntlm-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-ntlm-info.nse

User Summary
This script enumerates information from remote HTTP services with NTLM authentication enabled.
By sending a HTTP NTLM authentication request with null domain and user credentials (passed in the 'Authorization'
header), the remote service will respond with a NTLMSSP message (encoded within the 'WWW-Authenticate' header)
and disclose information to include NetBIOS, DNS, and OS build version if available.

Script Arguments
http-ntlm-info.root
The URI path to request
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -p 80 --script http-ntlm-info --script-args http-ntlm-info.root=/root/ <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script  http-ntlm-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-ntlm-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "63":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-open-proxy

Script types: portrule
Categories: default, discovery, external, safe
Download: http://nmap.org/svn/scripts/http-open-proxy.nse

User Summary
Checks if an HTTP proxy is open.
The script attempts to connect to www.google.com through the proxy and checks for a valid HTTP response code.
Valid HTTP response codes are 200, 301, and 302. If the target is an open proxy, this script causes the target to
retrieve a web page from www.google.com.

Script Arguments
proxy.url
Url that will be requested to the proxy
proxy.pattern
Pattern that will be searched inside the request results

Example Usage
nmap --script http-open-proxy.nse \
     --script-args proxy.url=<url>,proxy.pattern=<pattern>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script http-open-proxy'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-open-proxy -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)    
    elif option == "64":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-open-redirect

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-open-redirect.nse

User Summary
Spiders a website and attempts to identify open redirects. Open redirects are handlers which commonly take a URL
as a parameter and responds with a http redirect (3XX) to the target. Risks of open redirects are described at
http://cwe.mitre.org/data/definitions/601.html.

Script Arguments
http-open-redirect.maxdepth
the maximum amount of directories beneath the initial url to spider. A negative value disables the limit. (default: 3)
http-open-redirect.maxpagecount
the maximum amount of pages to visit. A negative value disables the limit (default: 20)
http-open-redirect.url
the url to start spidering. This is a URL relative to the scanned host eg. /default.html (default: /)
http-open-redirect.withindomain
only spider URLs within the same domain. This widens the scope from withinhost and can not be used in combination. (default: false)
http-open-redirect.withinhost
only spider URLs within the same host. (default: true)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-open-redirect <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-open-redirect'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-open-redirect -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "65":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-passwd

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/http-passwd.nse

User Summary
Checks if a web server is vulnerable to directory traversal by attempting to retrieve /etc/passwd or \boot.ini.
The script uses several technique:
    Generic directory traversal by requesting paths like ../../../../etc/passwd.
    Known specific traversals of several web servers.
    Query string traversal. This sends traversals as query string parameters to paths that look like they refer
    to a local file name. The potential query is searched for in at the path controlled by the script argument http-passwd.root.

Script Arguments
http-passwd.root
Query string tests will be done relative to this path. The default value is /. Normally the value should contain a leading slash.
The queries will be sent with a trailing encoded null byte to evade certain checks; see http://insecure.org/news/P55-01.txt.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-passwd --script-args http-passwd.root=/test/ <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-passwd'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-passwd -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)    
    elif option == "66":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-php-version

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-php-version.nse

User Summary
Attempts to retrieve the PHP version from a web server. PHP has a number of magic queries that return images or
text that can vary with the PHP version.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script=http-php-version <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-php-version'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-php-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "67":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-phpmyadmin-dir-traversal

Script types: portrule
Categories: vuln, exploit
Download: http://nmap.org/svn/scripts/http-phpmyadmin-dir-traversal.nse

User Summary
Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and possibly other versions) to retrieve
remote files on the web server.

Script Arguments
http-phpmyadmin-dir-traversal.dir
Basepath to the services page. Default: /phpMyAdmin-2.6.4-pl1/
http-phpmyadmin-dir-traversal.file
Remote file to retrieve. Default: ../../../../../etc/passwd
http-phpmyadmin-dir-traversal.outfile
Output file
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -p80 --script http-phpmyadmin-dir-traversal --script-args="dir='/pma/',file='../../../../../../../../etc/passwd',outfile='passwd.txt'" <host/ip>
nmap -p80 --script http-phpmyadmin-dir-traversal <host/ip>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script  http-phpmyadmin-dir-traversal -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-phpmyadmin-dir-traversal -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "68":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-phpself-xss

Script types: portrule
Categories: fuzzer, intrusive, vuln
Download: http://nmap.org/svn/scripts/http-phpself-xss.nse

User Summary
Crawls a web server and attempts to find PHP files vulnerable to reflected cross site scripting via the variable $_SERVER["PHP_SELF"].
This script crawls the webserver to create a list of PHP files and then sends an attack vector/probe to identify PHP_SELF cross site scripting vulnerabilities. PHP_SELF XSS refers to reflected cross site scripting vulnerabilities caused by the lack of sanitation of the variable $_SERVER["PHP_SELF"] in PHP scripts. This variable is commonly used in PHP scripts that display forms and when the script file name is needed.

Script Arguments
http-phpself-xss.timeout
Spidering timeout. (default 10s)
http-phpself-xss.uri
URI. Default: /
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,
httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
vulns.showall
See the documentation for the vulns library.
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap --script=http-phpself-xss -p80 <target>
nmap -sV --script http-self-xss <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-phpself-xss -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-phpself-xss -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "69":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-proxy-brute

Script types: portrule
Categories: brute, intrusive, external
Download: http://nmap.org/svn/scripts/http-proxy-brute.nse

User Summary
Performs brute force password guessing against HTTP proxy servers.

Script Arguments
http-proxy-brute.url
sets an alternative URL to use when brute forcing (default: http://scanme.insecure.org)
http-proxy-brute.method
changes the HTTP method to use when performing brute force guessing (default: HEAD)
creds.[service], creds.global
See the documentation for the creds library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode,
brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap --script http-proxy-brute -p 8080 <host>

Default Option Used in script:
nmap -p 8080 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-8080[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-proxy-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-proxy-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "70":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-put

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-put.nse

User Summary
Uploads a local file to a remote web server using the HTTP PUT method. You must specify the filename and
URL path with NSE arguments.

Script Arguments
http-put.file
- The full path to the local file that should be uploaded to the server
http-put.url
- The remote directory and filename to store the file to e.g. (/uploads/file.txt)
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 80 <ip> --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php'

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-put -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-put -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "71":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-qnap-nas-info

Script types: portrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/http-qnap-nas-info.nse

User Summary
Attempts to retrieve the model, firmware version, and enabled services from a QNAP Network Attached Storage (NAS) device.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-qnap-nas-info -p <port> <host>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-qnap-nas-info'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-qnap-nas-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)     
    elif option == "72":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-referer-checker

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-referer-checker.nse

User Summary
Informs about cross-domain include of scripts. Websites that include external javascript scripts are
 delegating part of their security to third-party entities.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url,
httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-referer-checker.nse <host>

This script informs about cross-domain include of scripts by
finding src attributes that point to a different domain.

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-referer-checker -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-referer-checker -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "73":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-rfi-spider

Script types: portrule
Categories: intrusive
Download: http://nmap.org/svn/scripts/http-rfi-spider.nse

User Summary
Crawls webservers in search of RFI (remote file inclusion) vulnerabilities. It tests every form field it
finds and every parameter of a URL containing a query.

Script Arguments
http-rfi-spider.withinhost
only spider URLs within the same host. (default: true)
http-rfi-spider.url
the url to start spidering. This is a URL relative to the scanned host eg. /default.html (default: /)
http-rfi-spider.withindomain
only spider URLs within the same domain. This widens the scope from withinhost and can not be used in combination. (default: false)
http-rfi-spider.inclusionurl
the url we will try to include, defaults to http://tools.ietf.org/html/rfc13?
http-rfi-spider.maxdepth
the maximum amount of directories beneath the initial url to spider. A negative value disables the limit. (default: 3)
http-rfi-spider.maxpagecount
the maximum amount of pages to visit. A negative value disables the limit (default: 20)
http-rfi-spider.pattern
the pattern to search for in response.body to determine if the inclusion was successful, defaults to '20 August 1969'
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-rfi-spider -p80 <host>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-rfi-spider -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-rfi-spider -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "74":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-robots.txt

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-robots.txt.nse

User Summary
Checks for disallowed entries in /robots.txt on a web server.
The higher the verbosity or debug level, the more disallowed entries are shown.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV -sC <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-robots.txt.nse'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-robots.txt.nse -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "75":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-robtex-reverse-ip

Script types: prerule
Categories: discovery, safe, external
Download: http://nmap.org/svn/scripts/http-robtex-reverse-ip.nse

User Summary
Obtains up to 100 forward DNS names for a target IP address by querying the Robtex service (http://www.robtex.com/ip/).

Script Arguments
http-robtex-reverse-ip.host
IPv4 address of the host to lookup
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-robtex-reverse-ip --script-args http-robtex-reverse-ip.host='<ip>'

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-robtex-reverse-ip'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-robtex-reverse-ip -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "76":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-robtex-shared-ns

Script types: hostrule
Categories: discovery, safe, external
Download: http://nmap.org/svn/scripts/http-robtex-shared-ns.nse

User Summary
Finds up to 100 domain names which use the same name server as the target by querying the Robtex service at
http://www.robtex.com/dns/.
The target must be specified by DNS name, not IP address.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-robtex-shared-ns

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-robtex-shared-ns'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-robtex-shared-ns -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "77":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-server-header

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/http-server-header.nse
User Summary

Uses the HTTP Server header for missing version info. This is currently infeasible with version probes because of the need to match non-HTTP services correctly.
Example Usage

nmap -sV <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-server-header'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-server-header -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "78":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-shellshock

Script types: portrule
Categories: exploit, vuln, intrusive
Download: http://nmap.org/svn/scripts/http-shellshock.nse

User Summary
Attempts to exploit the "shellshock" vulnerability (CVE-2014-6271 and CVE-2014-7169) in web applications.
To detect this vulnerability the script executes a command that prints a random string and then attempts to find it inside
the response body. Web apps that don't print back information won't be detected with this method.
By default the script injects the payload in the HTTP headers User-Agent, Cookie, Referer and also uses the payload as the header name.
Vulnerability originally discovered by Stephane Chazelas.
References:

    http://www.openwall.com/lists/oss-security/2014/09/24/10
    http://seclists.org/oss-sec/2014/q3/685
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271

Script Arguments
http-shellshock.uri
URI. Default: /
http-shellshock.header
HTTP header to use in requests. Default: User-Agent
http-shellshock.cmd
Custom command to send inside payload. Default: nil
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV -p- --script http-shellshock <target>
nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls <target>

Default Option Used in script:
nmap  -sV -p- --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -p- --script http-shellshock'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-shellshock -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "79":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-sitemap-generator

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-sitemap-generator.nse

User Summary
Spiders a web server and displays its directory structure along with number and types of files in each folder. Note
that files listed as having an 'Other' extension are ones that have no extension or that are a root document.

Script Arguments
http-sitemap-generator.withindomain
only spider URLs within the same domain. This widens the scope from withinhost and can not be used in combination. (default: false)
http-sitemap-generator.maxdepth
the maximum amount of directories beneath the initial url to spider. A negative value disables the limit. (default: 3)
http-sitemap-generator.maxpagecount
the maximum amount of pages to visit. A negative value disables the limit (default: 20)
http-sitemap-generator.url
the url to start spidering. This is a URL relative to the scanned host eg. /default.html (default: /)
http-sitemap-generator.withinhost
only spider URLs within the same host. (default: true)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-sitemap-generator -p 80 <host>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-sitemap-generator -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-sitemap-generator -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "80":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-slowloris-check

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/http-slowloris-check.nse

User Summary
Tests a web server for vulnerability to the Slowloris DoS attack without actually launching a DoS attack.
Slowloris was described at Defcon 17 by RSnake (see http://ha.ckers.org/slowloris/).
This script opens two connections to the server, each without the final CRLF. After 10 seconds, second connection sends additional header.
Both connections then wait for server timeout. If second connection gets a timeout 10 or more seconds after the first one, we can conclude
that sending additional header prolonged its timeout and that the server is vulnerable to slowloris DoS attack.
A "LIKELY VULNERABLE" result means a server is subject to timeout-extension attack, but depending on the http server's architecture and r
esource limits, a full denial-of-service is not always possible. Complete testing requires triggering the actual DoS condition and measuring
server responsiveness.
You can specify custom http User-agent field with http.useragent script argument.

Idea from Qualys blogpost:
    https://community.qualys.com/blogs/securitylabs/2011/07/07/identifying-slow-http-attack-vulnerabilities-on-web-applications

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script http-slowloris-check  <target>

Default Option Used in script:
nmap   --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-slowloris-check'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-slowloris-check -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "81":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-slowloris

Script types: portrule
Categories: dos, intrusive
Download: http://nmap.org/svn/scripts/http-slowloris.nse

User Summary
Tests a web server for vulnerability to the Slowloris DoS attack by launching a Slowloris attack.

Script Arguments
http-slowloris.runforever
Specify that the script should continue the attack forever. Defaults to false.
http-slowloris.timelimit
Specify maximum run time for DoS attack (30 minutes default).
http-slowloris.send_interval

Time to wait before sending new http header datas in order to maintain the connection. Defaults to 100 seconds.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-slowloris --max-parallelism 400  <target>

Default Option Used in script:
nmap   --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-slowloris'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-slowloris -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "82":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-sql-injection

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/http-sql-injection.nse

User Summary
Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL injection attack. It also extracts
forms from found websites and tries to identify fields that are vulnerable.
The script spiders an HTTP server looking for URLs containing queries. It then proceeds to combine crafted SQL commands
with susceptible URLs in order to obtain errors. The errors are analysed to see if the URL is vulnerable to attack.
This uses the most basic form of SQL injection but anything more complicated is better suited to a standalone tool.
We may not have access to the target web server's true hostname, which can prevent access to virtually hosted sites.

Script Arguments
http-sql-injection.withinhost
only spider URLs within the same host. (default: true)
http-sql-injection.errorstrings
a path to a file containing the error strings to search for (one per line, lines started with # are treated as comments).
The default file is nselib/data/http-sql-errors.lst which was taken from fuzzdb project, for more info, see http://code.google.com/p/fuzzdb/.
If someone detects some strings in that file causing a lot of false positives, then please report them to dev@nmap.org.
http-sql-injection.withindomain
only spider URLs within the same domain. This widens the scope from withinhost and can not be used in combination. (default: false)
http-sql-injection.url
the url to start spidering. This is a URL relative to the scanned host eg. /default.html (default: /)
http-sql-injection.maxpagecount
the maximum amount of pages to visit. A negative value disables the limit (default: 20)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,
httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script=http-sql-injection <target>

Default Option Used in script:
nmap  -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-sql-injection'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-sql-injection -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "83":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-stored-xss

Script types: portrule
Categories: intrusive, exploit, vuln
Download: http://nmap.org/svn/scripts/http-stored-xss.nse

User Summary
Unfiltered '>' (greater than sign). An indication of potential XSS vulnerability.

Script Arguments
http-stored-xss.formpaths
The pages that contain the forms to exploit. For example, {/upload.php, /login.php}. Default: nil (crawler mode on)
http-stored-xss.uploadspaths
The pages that reflect back POSTed data. For example, {/comments.php, /guestbook.php}. Default: nil (Crawler mode on)
http-stored-xss.fieldvalues
The script will try to fill every field found in the form but that may fail due to fields' restrictions. You can manually fill those
fields using this table. For example, {gender = "male", email = "foo@bar.com"}. Default: {}
http-stored-xss.dbfile
The path of a plain text file that contains one XSS vector per line. Default: nil
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles,
httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-stored-xss.nse <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-stored-xss -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-stored-xss -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)          
    elif option == "84":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-svn-enum

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-svn-enum.nse

User Summary
Enumerates users of a Subversion repository by examining logs of most recent commits.

Script Arguments
http-svn-enum.url
This is a URL relative to the scanned host eg. /default.html (default: /).
http-svn-enum.count
The number of logs to fetch. Defaults to the last 1000 commits.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-svn-enum <target>

Default Option Used in script:
nmap   --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-svn-enum'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-svn-enum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "85":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-svn-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-svn-info.nse

User Summary
Requests information from a Subversion repository.

Script Arguments
http-svn-info.url
This is a URL relative to the scanned host eg. /default.html (default: /)
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-svn-info <target>

Default Option Used in script:
nmap   --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-svn-info'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-svn-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "86":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-title

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/http-title.nse

User Summary
Shows the title of the default page of a web server.
The script will follow up to 5 HTTP redirects, using the default rules in the http library.

Script Arguments
http-title.url
The url to fetch. Default: /
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV -sC <target>

Default Option Used in script:
nmap  -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-title'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-title -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "87":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-tplink-dir-traversal

Script types: portrule
Categories: vuln, exploit
Download: http://nmap.org/svn/scripts/http-tplink-dir-traversal.nse

User Summary
Exploits a directory traversal vulnerability existing in several TP-Link wireless routers. Attackers may exploit this
vulnerability to read any of the configuration and password files remotely and without authentication.
This vulnerability was confirmed in models WR740N, WR740ND and WR2543ND but there are several models that use the same
HTTP server so I believe they could be vulnerable as well. I appreciate any help confirming the vulnerability in other models.

Script Arguments
http-tplink-dir-traversal.rfile
Remote file to download. Default: /etc/passwd
http-tplink-dir-traversal.outfile
If set it saves the remote file to this location.
Other arguments you might want to use with this script:
    http.useragent - Sets user agent
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
    nmap -p80 --script http-tplink-dir-traversal.nse <target>
    nmap -p80 -Pn -n --script http-tplink-dir-traversal.nse <target>
    nmap -p80 --script http-tplink-dir-traversal.nse --script-args rfile=/etc/topology.conf -d -n -Pn <target>

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-tplink-dir-traversal -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-tplink-dir-traversal -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "88":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-trace

Script types: portrule
Categories: vuln, discovery, safe
Download: http://nmap.org/svn/scripts/http-trace.nse

User Summary
Sends an HTTP TRACE request and shows if the method TRACE is enabled. If debug is enabled, it returns the header fields that were modified in the response.

Script Arguments
http-trace.path
Path to URI
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-trace -d <ip>

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-trace -d '+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-trace -d -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "89":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-tracerouteroute

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-tracerouteroute.nse

User Summary
Exploits the Max-Forwards HTTP header to detect the presence of reverse proxies.
The script works by sending HTTP requests with values of the Max-Forwards HTTP header varying from 0 to 2 and
checking for any anomalies in certain response values such as the status code, Server, Content-Type and Content-Length
HTTP headers and body values such as the HTML title.

Script Arguments
http-tracerouteroute.path
The path to send requests to. Defaults to /.
http-tracerouteroute.method
HTTP request method to use. Defaults to GET. Among other values, TRACE is probably the most interesting.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-tracerouteroute <targets>

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-traceroute'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-traceroute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "90":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File http-unsafe-output-escaping

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-unsafe-output-escaping.nse

User Summary
Spiders a website and attempts to identify output escaping problems where content is reflected back to the user. This script locates all parameters, ?x=foo&y=bar and checks if the values are reflected on the page. If they are indeed reflected, the script will try to insert ghz>hzx"zxc'xcv and check which (if any) characters were reflected back onto the page without proper html escaping. This is an indication of potential XSS vulnerability.

Script Arguments
http-unsafe-output-escaping.withinhost
only spider URLs within the same host. (default: true)
http-unsafe-output-escaping.url
the url to start spidering. This is a URL relative to the scanned host eg. /default.html (default: /)
http-unsafe-output-escaping.maxdepth
the maximum amount of directories beneath the initial url to spider. A negative value disables the limit. (default: 3)
http-unsafe-output-escaping.withindomain
only spider URLs within the same domain. This widens the scope from withinhost and can not be used in combination. (default: false)
http-unsafe-output-escaping.maxpagecount
the maximum amount of pages to visit. A negative value disables the limit (default: 20)
slaxml.debug
See the documentation for the slaxml library.
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-unsafe-output-escaping <target>

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-unsafe-output-escaping'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-unsafe-output-escaping -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "91":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-useragent-tester

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-useragent-tester.nse

User Summary
Checks if various crawling utilities are allowed by the host.

Script Arguments
http-useragent-tester.useragents

A table with more User-Agent headers. Default: nil
httpspider.doscraping, httpspider.maxdepth, httpspider.maxpagecount, httpspider.noblacklist, httpspider.url, httpspider.useheadfornonwebfiles, httpspider.withindomain, httpspider.withinhost
See the documentation for the httpspider library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
max-newtargets, newtargets
See the documentation for the target library.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -p80 --script http-useragent-tester.nse <host>

This script sets various User-Agent headers that are used by different
utilities and crawling libraries (for example CURL or wget). If the request is
redirected to a page different than a (valid) browser request would be, that
means that this utility is banned.

Default Option Used in script:
nmap -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-useragent-tester -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-useragent-tester -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "92":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-userdir-enum

Script types: portrule
Categories: auth, intrusive
Download: http://nmap.org/svn/scripts/http-userdir-enum.nse

User Summary
Attempts to enumerate valid usernames on web servers running with the mod_userdir module or similar enabled.
The Apache mod_userdir module allows user-specific directories to be accessed using the http://example.com/~user/ syntax.
This script makes http requests in order to discover valid user-specific directories and infer valid usernames. By default,
the script will use Nmap's nselib/data/usernames.lst. An HTTP response status of 200 or 403 means the username is likely a
valid one and the username will be output in the script results along with the status code (in parentheses).
This script makes an attempt to avoid false positives by requesting a directory which is unlikely to exist. If the server
responds with 200 or 403 then the script will not continue testing it.
CVE-2001-1013: http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2001-1013.

Script Arguments
userdir.users
The filename of a username list.
limit
The maximum number of users to check.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script=http-userdir-enum <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-userdir-enum'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-userdir-enum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "93":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vhosts

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-vhosts.nse

User Summary
Searches for web virtual hostnames by making a large number of HEAD requests against http servers using common hostnames.
Each HEAD request provides a different Host header. The hostnames come from a built-in default list. Shows the names that
return a document. Also shows the location of redirections.
The domain can be given as the http-vhosts.domain argument or deduced from the target's name. For example when scanning www.example.com,
various names of the form <name>.example.com are tried.

Script Arguments
http-vhosts.filelist
file with the vhosts to try. Default nselib/data/vhosts-default.lst
http-vhosts.collapse
The limit to start collapsing results by status code. Default 20
http-vhosts.path
The path to try to retrieve. Default /.
http-vhosts.domain
The domain that hostnames will be prepended to, for example example.com yields www.example.com, www2.example.com, etc. If not provided, a guess is made based on the hostname.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-vhosts -p 80,8080,443 <target>

Default Option Used in script:
nmap -p 80,8080,443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,8080,443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,8080,443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vhosts -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vhosts -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)         
    elif option == "94":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-virustotal

Script types: prerule
Categories: safe, malware, external
Download: http://nmap.org/svn/scripts/http-virustotal.nse

User Summary
Checks whether a file has been determined as malware by Virustotal. Virustotal is a service that provides the capability to scan
a file or check a checksum against a number of the major antivirus vendors. The script uses the public API which requires a valid
API key and has a limit on 4 queries per minute. A key can be acquired by registering as a user on the virustotal web page:
    http://www.virustotal.com
The scripts supports both sending a file to the server for analysis or checking whether a checksum (supplied as an argument or calculated
from a local file) was previously discovered as malware.
As uploaded files are queued for analysis, this mode simply returns a URL where status of the queued file may be checked.

Script Arguments
http-virustotal.checksum
a SHA1, SHA256, MD5 checksum of a file to check
http-virustotal.apikey
an API key acquired from the virustotal web page
http-virustotal.upload
true if the file should be uploaded and scanned, false if a checksum should be calculated of the local file (default: false)
http-virustotal.filename
the full path of the file to checksum or upload
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-virustotal --script-args='http-virustotal.apikey="<key>",http-virustotal.checksum="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"'

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-virustotal'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-virustotal -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "95":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File http-vlcstreamer-ls

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/http-vlcstreamer-ls.nse

User Summary
Connects to a VLC Streamer helper service and lists directory contents. The VLC Streamer helper service is used by the iOS VLC Streamer application to enable streaming of multimedia content from the remote server to the device.

Script Arguments
http-vlcstreamer-ls.dir
directory to list (default: /)
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 54340 --script http-vlcstreamer-ls <ip>

Default Option Used in script:
nmap -p 54340 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-54340Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="54340"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vlcstreamer -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vlcstreamer -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "96":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File http-vmware-path-vuln

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/http-vmware-path-vuln.nse

User Summary
Checks for a path-traversal vulnerability in VMWare ESX, ESXi, and Server (CVE-2009-3733).
The vulnerability was originally released by Justin Morehouse and Tony Flick, who presented at Shmoocon 2010 (
http://fyrmassociates.com/tools.html).

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-vmware-path-vuln -p80,443,8222,8333 <host>

Default Option Used in script:
nmap -p 80,443,8222,8333 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,443,8222,8333[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,443,8222,8333"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vmware-path-vuln-p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vmware-path-vuln-p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "97":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File http-vuln-cve2006-3392

Script types: portrule
Categories: exploit, vuln, intrusive
Download: http://nmap.org/svn/scripts/http-vuln-cve2006-3392.nse

User Summary
Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392)
Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences to
bypass the removal of "../" directory traversal sequences.

Script Arguments
http-vuln-cve2006-3392.file
<FILE>. Default: /etc/passwd
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script http-vuln-cve2006-3392 <target>
nmap -p80 --script http-vuln-cve2006-3392 --script-args http-vuln-cve2006-3392.file=/etc/shadow <target>

Default Option Used in script:
nmap -sV -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2006-3392 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2006-3392 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "98":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File http-vuln-cve2009-3960

Script types: portrule
Categories: exploit, intrusive
Download: http://nmap.org/svn/scripts/http-vuln-cve2009-3960.nse

User Summary
Exploits cve-2009-3960 also known as Adobe XML External Entity Injection.
This vulnerability permits to read local files remotely and is present in BlazeDS 3.2 and earlier, LiveCycle 8.0.1,
8.2.1, and 9.0, LiveCycle Data Services 2.5.1, 2.6.1, and 3.0, Flex Data Services 2.0.1, and ColdFusion 7.0.2, 8.0, 8.0.1, and 9.0
For more information see:
    http://www.security-assessment.com/files/advisories/2010-02-22_Multiple_Adobe_Products-XML_External_Entity_and_XML_Injection.pdf
    http://www.osvdb.org/62292
    Metasploit module: auxiliary/scanner/http/adobe_xml_inject

Script Arguments
http-vuln-cve2009-3960.root
Points to the root path. Defaults to "/"
http-vuln-cve2009-3960.readfile
target file to be read. Defaults to "/etc/passwd"
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script=http-vuln-cve2009-3960 --script-args http-http-vuln-cve2009-3960.root="/root/" <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vuln-cve2009-3960 -p '+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vuln-cve2009-3960 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "99":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2010-0738

Script types: portrule
Categories: safe, auth, vuln
Download: http://nmap.org/svn/scripts/http-vuln-cve2010-0738.nse

User Summary
Tests whether a JBoss target is vulnerable to jmx console authentication bypass (CVE-2010-0738).
It works by checking if the target paths require authentication or redirect to a login page that could be bypassed
via a HEAD request. RFC 2616 specifies that the HEAD request should be treated exactly like GET but with no returned
response body. The script also detects if the URL does not require authentication at all.
For more information, see:
    CVE-2010-0738 http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0738
    http://www.imperva.com/resources/glossary/http_verb_tampering.html
    https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29

Script Arguments
http-vuln-cve2010-0738.paths
Array of paths to check. Defaults to {"/jmx-console/"}.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-vuln-cve2010-0738 --script-args 'http-vuln-cve2010-0738.paths={/path1/,/path2/}' <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vuln-cve2010-0738'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script http-vuln-cve2010-0738 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "100":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2010-2861

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/http-vuln-cve2010-2861.nse

User Summary
Executes a directory traversal attack against a ColdFusion server and tries to grab the password hash for the administrator user. It then uses the salt value (hidden in the web page) to create the SHA1 HMAC hash that the web server needs for authentication as admin. You can pass this value to the ColdFusion server as the admin without cracking the password hash.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script http-vuln-cve2010-2861 <host>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-vuln-cve2010-2861'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script  http-vuln-cve2010-2861 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "101":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2011-3192

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/http-vuln-cve2011-3192.nse

User Summary
Detects a denial of service vulnerability in the way the Apache web server handles requests for multiple overlapping/simple ranges of a page.
References:
    http://seclists.org/fulldisclosure/2011/Aug/175
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
    http://nessus.org/plugins/index.php?view=single&id=55976

Script Arguments
http-vuln-cve2011-3192.path
Define the request path
http-vuln-cve2011-3192.hostname
Define the host name to be used in the HEAD request sent to the server
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script http-vuln-cve2011-3192.nse [--script-args http-vuln-cve2011-3192.hostname=nmap.scanme.org] -pT:80,443 <host>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-vuln-cve2011-3192'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script  http-vuln-cve2011-3192 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "102":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2011-3368

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/http-vuln-cve2011-3368.nse

User Summary
Tests for the CVE-2011-3368 (Reverse Proxy Bypass) vulnerability in Apache HTTP server's reverse proxy mode. The script will run 3 tests:
    the loopback test, with 3 payloads to handle different rewrite rules
    the internal hosts test. According to Contextis, we expect a delay before a server error.
    The external website test. This does not mean that you can reach a LAN ip, but this is a relevant issue anyway.

Script Arguments
http-vuln-cve2011-3368.prefix
sets the path prefix (directory) to check for the vulnerability.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script http-vuln-cve2011-3368 <targets>ost>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  http-vuln-cve2011-3368'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script  http-vuln-cve2011-3368 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)                
    elif option == "103":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File http-vuln-cve2012-1823

Script types: portrule
Categories: exploit, vuln, intrusive
Download: http://nmap.org/svn/scripts/http-vuln-cve2012-1823.nse

User Summary
Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This critical vulnerability allows attackers to retrieve
source code and execute code remotely.
The script works by appending "?-s" to the uri to make vulnerable php-cgi handlers return colour syntax highlighted source.
We use the pattern "<span style=.*>&lt;?" to detect vulnerable installations.

Script Arguments
http-vuln-cve2012-1823.uri
URI. Default: /index.php
http-vuln-cve2012-1823.cmd
CMD. Default: uname -a
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script http-vuln-cve2012-1823 <target>
nmap -p80 --script http-vuln-cve2012-1823 --script-args http-vuln-cve2012-1823.uri=/test.php <target>

Default Option Used in script:
nmap -sV -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2012-1823 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2012-1823 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "104":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


File http-vuln-cve2013-0156

Script types: portrule
Categories: exploit, vuln
Download: http://nmap.org/svn/scripts/http-vuln-cve2013-0156.nse

User Summary
Detects Ruby on Rails servers vulnerable to object injection, remote command executions and denial of service attacks. (CVE-2013-0156)
All Ruby on Rails versions before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10, and 3.2.x before 3.2.11 are vulnerable.
This script sends 3 harmless YAML payloads to detect vulnerable installations. If the malformed object receives a status 500 response,
the server is processing YAML objects and therefore is likely vulnerable.

Script Arguments
http-vuln-cve2013-0156.uri
Basepath URI (default: /).
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script http-vuln-cve2013-0156 <target>
nmap -sV --script http-vuln-cve2013-0156 --script-args uri="/test/" <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2013-0156'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2013-0156 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "104":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2013-0156

Script types: portrule
Categories: exploit, vuln
Download: http://nmap.org/svn/scripts/http-vuln-cve2013-0156.nse

User Summary
Detects Ruby on Rails servers vulnerable to object injection, remote command executions and denial of service attacks. (CVE-2013-0156)
All Ruby on Rails versions before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10, and 3.2.x before 3.2.11 are vulnerable.
This script sends 3 harmless YAML payloads to detect vulnerable installations. If the malformed object receives a status 500 response,
the server is processing YAML objects and therefore is likely vulnerable.

Script Arguments
http-vuln-cve2013-0156.uri
Basepath URI (default: /).
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script http-vuln-cve2013-0156 <target>
nmap -sV --script http-vuln-cve2013-0156 --script-args uri="/test/" <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2013-0156'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2013-0156 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "105":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File http-vuln-cve2013-6786

Script types: portrule
Categories: exploit, vuln
Download: http://nmap.org/svn/scripts/http-vuln-cve2013-6786.nse

User Summary
Detects a URL redirection and reflected XSS vulnerability in Allegro RomPager Web server. The vulnerability has
been assigned CVE-2013-6786.

The check is general enough (script tag injection via Referer header) that some other software may be vulnerable
in the same way.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
    nmap -p80 --script http-rompager-xss <target>
    nmap -sV http-rompager-xss <target>

Default Option Used in script:
nmap -sV -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-rompager-xss -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-rompager-xss -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "106":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2013-7091
Script types: portrule
Categories: exploit, vuln, intrusive
Download: http://nmap.org/svn/scripts/http-vuln-cve2013-7091.nse

User Summary
An 0 day was released on the 6th December 2013 by rubina119, and was patched in Zimbra 7.2.6.
The vulnerability is a local file inclusion that can retrieve any file from the server.
Currently, we read /etc/passwd and /dev/null, and compare the lengths to determine vulnerability.
TODO: Add the possibility to read compressed file. Then, send some payload to create the new mail account.

Script Arguments
http-vuln-cve2013-7091.uri
URI. Default: /zimbra
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script http-vuln-cve2013-7091 <target>
nmap -p80 --script http-vuln-cve2013-7091 --script-args http-vuln-cve2013-7091=/ZimBra <target>

Default Option Used in script:
nmap -sV -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2013-7091 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2013-7091 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "107":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2014-2126

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/http-vuln-cve2014-2126.nse

User Summary
Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA ASDM Privilege Escalation Vulnerability (CVE-2014-2126).

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
anyconnect.group, anyconnect.mac, anyconnect.ua, anyconnect.version
See the documentation for the anyconnect library.
vulns.showall
See the documentation for the vulns library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
slaxml.debug
See the documentation for the slaxml library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage 
nmap -p 443 --script http-vuln-cve2014-2126 <target>


Default Option Used in script:
nmap -sV -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2014-2126 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2014-2126 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "108":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2014-2127

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/http-vuln-cve2014-2127.nse
User Summary

Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN Privilege Escalation Vulnerability (CVE-2014-2127).
Script Arguments

mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
anyconnect.group, anyconnect.mac, anyconnect.ua, anyconnect.version
See the documentation for the anyconnect library.
vulns.showall
See the documentation for the vulns library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
slaxml.debug
See the documentation for the slaxml library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -p 443 --script http-vuln-cve2014-2127 <target>


Default Option Used in script:
nmap -sV -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2014-2127 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2014-2127 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "109":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2014-2128

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/http-vuln-cve2014-2128.nse

User Summary
Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN Authentication Bypass Vulnerability (CVE-2014-2128).

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
anyconnect.group, anyconnect.mac, anyconnect.ua, anyconnect.version
See the documentation for the anyconnect library.
vulns.showall
See the documentation for the vulns library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
slaxml.debug
See the documentation for the slaxml library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -p 443 --script http-vuln-cve2014-2128 <target>


Default Option Used in script:
nmap -sV -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2014-2128 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2014-2128 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "110":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2014-2129

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/http-vuln-cve2014-2129.nse

User Summary
Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SIP Denial of Service Vulnerability (CVE-2014-2129).

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
anyconnect.group, anyconnect.mac, anyconnect.ua, anyconnect.version
See the documentation for the anyconnect library.
vulns.showall
See the documentation for the vulns library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
slaxml.debug
See the documentation for the slaxml library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -p 443 --script http-vuln-cve2014-2129 <target>


Default Option Used in script:
nmap -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script http-vuln-cve2014-2129 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2014-2129 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "111":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2014-3704

Script types: portrule
Categories: vuln, intrusive, exploit
Download: http://nmap.org/svn/scripts/http-vuln-cve2014-3704.nse

User Summary
Exploits CVE-2014-3704 also known as 'Drupageddon' in Drupal. Versions < 7.32 of Drupal core are known to be affected.
Vulnerability allows remote attackers to conduct SQL injection attacks via an array containing crafted keys.
The script injects new Drupal administrator user via login form and then it attempts to log in as this user to determine if target is vulnerable. If that's the case following exploitation steps are performed:
    PHP filter module which allows embedded PHP code/snippets to be evaluated is enabled,
    permission to use PHP code for administrator users is set,
    new article which contains payload is created & previewed,
    cleanup: by default all DB records that were added/modified by the script are restored.
Vulnerability originally discovered by Stefan Horst from SektionEins.
Exploitation technique used to achieve RCE on the target is based on exploit/multi/http/drupal_drupageddon Metasploit module.

Script Arguments
http-vuln-cve2014-3704.uri
Drupal root directory on the website. Default: /
http-vuln-cve2014-3704.cmd
Shell command to execute. Default: nil
http-vuln-cve2014-3704.cleanup
Indicates whether cleanup (removing DB records that was added/modified during exploitation phase) will be done. Default: true
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.cmd="uname -a",http-vuln-cve2014-3704.uri="/drupal" <target>
nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.uri="/drupal",http-vuln-cve2014-3704.cleanup=false <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2014-3704'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2014-3704 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "112":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2014-8877

Script types: portrule
Categories: vuln, intrusive, exploit
Download: http://nmap.org/svn/scripts/http-vuln-cve2014-8877.nse

User Summary
Exploits a remote code injection vulnerability (CVE-2014-8877) in Wordpress CM Download Manager plugin. Versions <= 2.0.0
are known to be affected.
CM Download Manager plugin does not correctly sanitise the user input which allows remote attackers to execute arbitrary PHP
code via the CMDsearch parameter to cmdownloads/, which is processed by the PHP 'create_function' function.
The script injects PHP system() function into the vulnerable target in order to execute specified shell command.

Script Arguments
http-vuln-cve2014-8877.cmd
Command to execute. Default: nil
http-vuln-cve2014-8877.uri
Wordpress root directory on the website. Default: /
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script http-vuln-cve2014-8877 --script-args http-vuln-cve2014-8877.cmd="whoami",http-vuln-cve2014-8877.uri="/wordpress" <target>
nmap --script http-vuln-cve2014-8877 <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2014-8877'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2014-8877 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "113":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2015-1427

Script types: portrule
Categories: vuln, intrusive
Download: http://nmap.org/svn/scripts/http-vuln-cve2015-1427.nse

User Summary
This script attempts to detect a vulnerability, CVE-2015-1427, which allows attackers to leverage features of this API to gain unauthenticated remote code execution (RCE).
Elasticsearch versions 1.3.0-1.3.7 and 1.4.0-1.4.2 have a vulnerability in the Groovy scripting engine. The vulnerability allows an attacker to construct Groovy scripts that escape the sandbox and execute shell commands as the user running the Elasticsearch Java VM.

Script Arguments
command
Enter the shell comannd to be executed. The script outputs the Java and Elasticsearch versions by default.
invasive
If set to true then it creates an index if there are no indices.
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script=http-vuln-cve2015-1427 --script-args command= 'ls' <targets>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2015-1427'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-vuln-cve2015-1427 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "114":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-cve2015-1635

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/http-vuln-cve2015-1635.nse

User Summary
Checks for a remote code execution vulnerability (MS15-034) in Microsoft Windows systems (CVE2015-2015-1635).
The script sends a specially crafted HTTP request with no impact on the system to detect this vulnerability. The affected versions are Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, and Windows Server 2012 R2.

Script Arguments
http-vuln-cve2015-1635.uri
URI to use in request. Default: /
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.
Example Usage
    nmap -sV --script vuln <target>
    nmap -p80 --script http-vuln-cve2015-1635.nse <target>
    nmap -sV --script http-vuln-cve2015-1635 --script-args uri='/anotheruri/' <target>

Default Option Used in script:
nmap -sV -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2015-1635 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-cve2015-1635 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "115":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-misfortune-cookie

Script types: portrule
Categories: vuln, intrusive
Download: http://nmap.org/svn/scripts/http-vuln-misfortune-cookie.nse

User Summary
Detects the RomPager 4.07 Misfortune Cookie vulnerability by safely exploiting it.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap <target> -p 7547 --script=http-vuln-misfortune-cookie

Default Option Used in script:
nmap -sV -p 7547 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-7547[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="7547"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-misfortune-cookie -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-misfortune-cookie -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "116":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-vuln-wnr1000-creds

Script types: portrule
Categories: exploit, vuln, intrusive
Download: http://nmap.org/svn/scripts/http-vuln-wnr1000-creds.nse

User Summary
A vulnerability has been discovered in WNR 1000 series that allows an attacker to retrieve administrator credentials with the router interface. Tested On Firmware Version(s): V1.0.2.60_60.0.86 (Latest) and V1.0.2.54_60.0.82NA
Vulnerability discovered by c1ph04.

Script Arguments
http-vuln-wnr1000-creds.uri
URI path where the passwordrecovered.cgi script can be found. Default: /
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script http-vuln-wnr1000-creds <target> -p80

Default Option Used in script:
nmap -sV -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-wnr1000-creds -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-vuln-wnr1000-creds -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "117":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-waf-detect

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-waf-detect.nse

User Summary
Attempts to determine whether a web server is protected by an IPS (Intrusion Prevention System), IDS (Intrusion Detection
System) or WAF (Web Application Firewall) by probing the web server with malicious payloads and detecting changes in the response
code and body.
To do this the script will send a "good" request and record the response, afterwards it will match this response against new
requests containing malicious payloads. In theory, web applications shouldn't react to malicious requests because we are storing
the payloads in a variable that is not used by the script/file and only WAF/IDS/IPS should react to it. If aggro mode is set,
the script will try all attack vectors (More noisy)
This script can detect numerous IDS, IPS, and WAF products since they often protect web applications in the same way. But it won't detect products which don't alter the http traffic. Results can vary based on product configuration, but this script has been tested to work against various configurations of the following products:
    Apache ModSecurity
    Barracuda Web Application Firewall
    PHPIDS
    dotDefender
    Imperva Web Firewall
    Blue Coat SG 400

Script Arguments
http-waf-detect.uri
Target URI. Use a path that does not redirect to a different page
http-waf-detect.aggro
If aggro mode is set, the script will try all attack vectors to trigger the IDS/IPS/WAF
http-waf-detect.detectBodyChanges
If set it also checks for changes in the document's body
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-waf-detect <host>
nmap -p80 --script http-waf-detect --script-args="http-waf-detect.aggro,http-waf-detect.uri=/testphp.vulnweb.com/artists.php" www.modsecurity.org

Default Option Used in script:
nmap -sV -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-waf-detect -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-waf-detect -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "118":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-waf-fingerprint

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-waf-fingerprint.nse

User Summary
Tries to detect the presence of a web application firewall and its type and version.
This works by sending a number of requests and looking in the responses for known behavior and fingerprints such as Server header, cookies and headers values. Intensive mode works by sending additional WAF specific requests to detect certain behaviour.
Credit to wafw00f and w3af for some fingerprints.

Script Arguments
http-waf-fingerprint.root
The base path. Defaults to /.
http-waf-fingerprint.intensive
If set, will add WAF specific scans, which takes more time. Off by default.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=http-waf-fingerprint <targets>
nmap --script=http-waf-fingerprint --script-args http-waf-fingerprint.intensive=1 <targets>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-waf-fingerprint'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-waf-fingerprint -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "119":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-webdav-scan

Script types: portrule
Categories: safe, discovery, default
Download: http://nmap.org/svn/scripts/http-webdav-scan.nse

User Summary
A script to detect WebDAV installations. Uses the OPTIONS and PROPFIND methods.
The script sends an OPTIONS request which lists the dav type, server type, date and allowed methods. It then sends
a PROPFIND request and tries to fetch exposed directories and internal ip addresses by doing pattern matching in the response body.
This script takes inspiration from the various scripts listed here:
    http://carnal0wnage.attackresearch.com/2010/05/more-with-metasploit-and-webdav.html
    https://github.com/sussurro/Metasploit-Tools/blob/master/modules/auxiliary/scanner/http/webdav_test.rb
    http://code.google.com/p/davtest/

Script Arguments
http-webdav-scan.path
The path to start in; e.g. "/web/" will try "/web/xxx".
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script http-webdav-scan -p80,8080 <target>

Default Option Used in script:
nmap -sV -p 80,8080 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,8080[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-webdav-scan -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-webdav-scan -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "120":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-wordpress-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/http-wordpress-brute.nse

User Summary
performs brute force password auditing against Wordpress CMS/blog installations.
This script uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are stored using the credentials library.
Wordpress default uri and form names:
    Default uri:wp-login.php
    Default uservar: log
    Default passvar: pwd

Script Arguments
http-wordpress-brute.threads
sets the number of threads. Default: 3
Other useful arguments when using this script are:
    http.useragent = String - User Agent used in HTTP requests
    brute.firstonly = Boolean - Stop attack when the first credentials are found
    brute.mode = user/creds/pass - Username password iterator
    passdb = String - Path to password list
    userdb = String - Path to user list

Based on Patrik Karlsson's http-form-brute
http-wordpress-brute.uri
points to the file 'wp-login.php'. Default /wp-login.php
http-wordpress-brute.uservar
sets the http-variable name that holds the username used to authenticate. Default: log
http-wordpress-brute.hostname
sets the host header in case of virtual hosting
http-wordpress-brute.passvar
sets the http-variable name that holds the password used to authenticate. Default: pwd
creds.[service], creds.global
See the documentation for the creds library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries,
brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -sV --script http-wordpress-brute <target>
nmap -sV --script http-wordpress-brute
  --script-args 'userdb=users.txt,passdb=passwds.txt,http-wordpress-brute.hostname=domain.com,
                 http-wordpress-brute.threads=3,brute.firstonly=true' <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-wordpress-brute'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-wordpress-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "121":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-wordpress-enum

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/http-wordpress-enum.nse

User Summary
Enumerates themes and plugins of Wordpress installations. The script can also detect outdated plugins by comparing
version numbers with information pulled from api.wordpress.org.

Script Arguments
http-wordpress-enum.type
Search type. Available options:plugins, themes or all. Default:all.
http-wordpress-enum.search-limit
Number of entries or the string "all". Default:100.
http-wordpress-enum.root
Base path. By default the script will try to find a WP directory installation or fall back to '/'.
http-wordpress-enum.check-latest
Retrieves latest plugin version information from wordpress.org. Default:false.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
    nmap -sV --script http-wordpress-enum <target>
    nmap --script http-wordpress-enum --script-args check-latest=true,search-limit=10 <target>
    nmap --script http-wordpress-enum --script-args type="themes" <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-wordpress-enum'+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  http-wordpress-enum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "122":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File http-wordpress-users

Script types: portrule
Categories: auth, intrusive, vuln
Download: http://nmap.org/svn/scripts/http-wordpress-users.nse

User Summary
Enumerates usernames in Wordpress blog/CMS installations by exploiting an information disclosure vulnerability existing in versions 2.6, 3.1, 3.1.1, 3.1.3 and 3.2-beta2 and possibly others.

Script Arguments
http-wordpress-users.out
If set it saves the username list in this file.
http-wordpress-users.basepath
Base path to Wordpress. Default: /
http-wordpress-users.limit
Upper limit for ID search. Default: 25
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-wordpress-users <target>
nmap -sV --script http-wordpress-users --script-args limit=50 <target>>

Default Option Used in script:
nmap -sV -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-wordpress-users -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-wordpress-users -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "123":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File http-xssed

Script types: portrule
Categories: safe, external, discovery
Download: http://nmap.org/svn/scripts/http-xssed.nse

User Summary
This script searches the xssed.com database and outputs the result.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p80 --script http-xssed.nse <target>

This script will search the xssed.com database and it will output any
results. xssed.com is the largest online archive of XSS vulnerable
websites.


Default Option Used in script:
nmap -sV -p 80 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-xssed -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script http-xssed -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            http(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)         
    elif option == "0":
        from ANSE import service_scan
        service_scan(host_ip, desc)
    else:
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)                 