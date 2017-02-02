def oracle(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Oracle:
    \t[1] oracle-brute-stealth\n\t[2] oracle-brute\n\t[3] oracle-enum-users\n\t[4] oracle-sid-brute\n\t[5] oracle-tns-version\n\t[6] ovs-agent-version
     \t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File oracle-brute-stealth

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/oracle-brute-stealth.nse

User Summary
Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's O5LOGIN authentication scheme. The vulnerability exists in Oracle 11g R1/R2 and allows linking the session key to a password hash. When initiating an authentication attempt as a valid user the server will respond with a session key and salt. Once received the script will disconnect the connection thereby not recording the login attempt. The session key and salt can then be used to brute force the users password.

Script Arguments
oracle-brute-stealth.johnfile
- if specified the hashes will be written to this file to be used by JtR
oracle-brute-stealth.accounts
- a list of comma separated accounts to test
oracle-brute-stealth.sid
- the instance against which to perform password guessing
oracle-brute-stealth.nodefault
- do not attempt to guess any Oracle default accounts
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
tns.sid
See the documentation for the tns library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL <host>

Default Option Used in script:
nmap -sV  -p 1521 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1521[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1521"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script oracle-brute-stealth -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script oracle-brute-stealth -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File oracle-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/oracle-brute.nse

User Summary
Performs brute force password auditing against Oracle servers.
Running it in default mode it performs an audit against a list of common Oracle usernames and passwords. The mode
can be changed by supplying the argument oracle-brute.nodefault at which point the script will use the username-
and password- lists supplied with Nmap. Custom username- and password- lists may be supplied using the userdb and
passdb arguments. The default credential list can be changed too by using the brute.credfile argument. In case the
userdb or passdb arguments are supplied, the script assumes that it should run in the nodefault mode.
In modern versions of Oracle password guessing speeds decrease after a few guesses and remain slow, due to connection throttling.
WARNING: The script makes no attempt to discover the amount of guesses that can be made before locking an account.
Running this script may therefor result in a large number of accounts being locked out on the database server.

Script Arguments
oracle-brute.sid
- the instance against which to perform password guessing
oracle-brute.nodefault
- do not attempt to guess any Oracle default accounts
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
tns.sid
See the documentation for the tns library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=ORCL <host>

Default Option Used in script:
nmap -sV  -p 1521 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1521[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1521"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script oracle-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script oracle-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File oracle-enum-users

Script types: portrule
Categories: intrusive, auth
Download: http://nmap.org/svn/scripts/oracle-enum-users.nse
User Summary

Attempts to enumerate valid Oracle user names against unpatched Oracle 11g servers (this bug was fixed in Oracle's October 2009 Critical Patch Update).

Script Arguments
oracle-enum-users.sid
the instance against which to attempt user enumeration
tns.sid
See the documentation for the tns library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt -p 1521-1560 <host>
If no userdb is supplied the default userlist is used

Default Option Used in script:
nmap -sV  -p 1521-1560 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1521-1560[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1521-1560"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script oracle-enum-users -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script oracle-enum-users -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File oracle-sid-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/oracle-sid-brute.nse

User Summary
Guesses Oracle instance/SID names against the TNS-listener.
If the oraclesids script argument is not used to specify an alternate file, the default oracle-sids file will be used. License to use the oracle-sids file was granted by its author, Alexander Kornbrust (http://seclists.org/nmap-dev/2009/q4/645).

Script Arguments
oraclesids
A file containing SIDs to try.

Example Usage
nmap --script=oracle-sid-brute --script-args=oraclesids=/path/to/sidfile -p 1521-1560 <host>
nmap --script=oracle-sid-brute -p 1521-1560 <host>

Default Option Used in script:
nmap -sV  -p 1521-1560 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1521-1560[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1521-1560"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script oracle-sid-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script oracle-sid-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File oracle-tns-version

Script types: portrule
Categories: version, safe
Download: http://nmap.org/svn/scripts/oracle-tns-version.nse

User Summary
Decodes the VSNNUM version number from an Oracle TNS listener.

Example Usage
nmap -sV <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script oracle-tns-version'+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script oracle-tns-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ovs-agent-version

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/ovs-agent-version.nse

User Summary
Detects the version of an Oracle Virtual Server Agent by fingerprinting responses to an HTTP GET request and an XML-RPC method call.
Version 2.2 of Virtual Server Agent returns a distinctive string in response to an HTTP GET request. However versions 3.0 and 3.0.1 return a generic response that looks like any other BaseHTTP/SimpleXMLRPCServer. Versions 2.2 and 3.0 return a distinctive error message in response to a system.listMethods XML-RPC call, which however does not distinguish the two versions. Version 3.0.1 returns a response to system.listMethods that is different from that of both version 2.2 and 3.0. Therefore we use this strategy: (1.) Send a GET request. If the version 2.2 string is returned, return "2.2". (2.) Send a system.listMethods method call. If an error is returned, return "3.0" or "3.0.1", depending on the specific format of the error.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV <target>>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ovs-agent-version'+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ovs-agent-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            oracle(host_ip,desc)
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