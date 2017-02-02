def ajp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Apache JServ Protocol
    [1] ajp-auth
    [2] ajp-brute
    [3] ajp-headers
    [4] ajp-methods
    [5] ajp-request
    [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ajp-auth

Script types: portrule
Categories: default, auth, safe
Download: http://nmap.org/svn/scripts/ajp-auth.nse

User Summary
Retrieves the authentication scheme and realm of an AJP service (Apache JServ Protocol) that requires authentication.
Script Arguments

ajp-auth.path
Argument example: [--script-args ajp-auth.path=/login]
Define the request path
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 8009 <ip> --script ajp-auth\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-8009 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8009"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  ajp-auth -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            arg=input("Enter argument if you need or press just enter:")
            subprocess.call('nmap --script  ajp-auth  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ajp-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/ajp-brute.nse

User Summary
Performs brute force passwords auditing against the Apache JServ protocol. The Apache JServ Protocol is commonly 
used by web servers to communicate with back-end Java application server containers.

Script Arguments
ajp-brute.path
creds.[service], creds.global
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
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
nmap -p 8009 <ip> --script ajp-brute\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-8009 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8009"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ajp-brute -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ajp-brute  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option  == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ajp-headers
Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ajp-headers.nse

User Summary
Performs a HEAD or GET request against either the root directory or any optional directory of an Apache JServ 
Protocol server and returns the server response headers.
Script Arguments
ajp-headers.path

The path to request, such as /index.php. Default /.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 8009 <ip> --script ajp-headers\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-8009 [Y/N/Nil]:")
        if port_select == "Y" or port_select == "y":
            default_port="8009"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ajp-headers -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ajp-headers  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        elif port_select == "Nil" or port_select == "nil":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ajp-headers '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ajp-methods

Script types: portrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/ajp-methods.nse

User Summary
Discovers which options are supported by the AJP (Apache JServ Protocol) server by sending an OPTIONS request
and lists potentially risky methods.
In this script, "potentially risky" methods are anything except GET, HEAD, POST, and OPTIONS. 
If the script reports potentially risky methods, they may not all be security risks, but you should check 
to make sure. This page lists the dangers of some common methods:
http://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29

Script Arguments
ajp-methods.path
the path to check or <code>/<code> if none was given
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 8009 <ip> --script ajp-methods\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-8009 [Y/N/Nil]:")
        if port_select == "Y" or port_select == "y":
            default_port="8009"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ajp-methods -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ajp-methods  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        elif port_select == "Nil" or port_select == "nil":
            arg=input("Enter argument if you need or press just enter:")
            subprocess.call('nmap --script ajp-methods '+arg+' '+host_ip,shell=True)
            ajp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ajp-request

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ajp-request.nse

User Summary
Requests a URI over the Apache JServ Protocol and displays the result (or stores it in a file).
Different AJP methods such as; GET, HEAD, TRACE, PUT or DELETE may be used.
The Apache JServ Protocol is commonly used by web servers to communicate with back-end Java application server
containers.

Script Arguments
username
the username to use to access protected resources
path
the path part of the URI to request
filename
the name of the file where the results should be stored
password
the password to use to access protected resources
method
AJP method to be used when requesting the URI (default: GET)
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 8009 <ip> --script ajp-request\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-8009 [Y/N/Nil]:")
        if port_select == "Y" or port_select == "y":
            default_port="548"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ajp-request -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ajp-request  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        elif port_select == "Nil" or port_select == "nil":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ajp-request '+arg+' '+host_ip+' '+output,shell=True)
            ajp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "0":
        from ANSE import service_scan
        service_scan(host_ip,desc)
    else:
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)
