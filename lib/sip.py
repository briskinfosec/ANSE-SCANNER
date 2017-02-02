def sip(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Session Initiation Protocol (SIP):
    \t[1] sip-brute\n\t[2] sip-call-spoof\n\t[3] sip-enum-users\n\t[4] sip-methods\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File sip-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/sip-brute.nse

User Summary
Performs brute force password auditing against Session Initiation Protocol (SIP) accounts. This protocol is most commonly associated with VoIP sessions.

Script Arguments
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
sip.timeout
See the documentation for the sip library.

Example Usage
nmap -sU -p 5060 <target> --script=sip-brute

Default Option Used in script:
nmap -sV -sU -p 5060 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-5060[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="5060"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script sip-brute -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            sip(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script sip-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            sip(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File sip-call-spoof

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/sip-call-spoof.nse

User Summary
Spoofs a call to a SIP phone and detects the action taken by the target (busy, declined, hung up, etc.)
This works by sending a fake sip invite request to the target phone and checking the responses. A response with status code 180 means that the phone is ringing. The script waits for the next responses until timeout is reached or a special response is received. Special responses include: Busy (486), Decline (603), Timeout (408) or Hang up (200).

Script Arguments
sip-call-spoof.from
Caller user ID. Defaults to Home.
sip-call-spoof.extension
SIP Extension to send request from. Defaults to 100.
sip-call-spoof.ua
Source application's user agent. Defaults to Ekiga.
sip-call-spoof.timeout
Time to wait for a response. Defaults to 5s
sip-call-spoof.src
Source address to spoof.
sip.timeout
See the documentation for the sip library.

Example Usage
nmap --script=sip-call-spoof -sU -p 5060 <targets>
nmap --script=sip-call-spoof -sU -p 5060 --script-args
'sip-call-spoof.ua=Nmap, sip-call-spoof.from=Boss' <targets>

Default Option Used in script:
nmap -sV -sU -p 5060 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-5060[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="5060"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script sip-call-spoof -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            sip(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script sip-call-spoof -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            sip(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File sip-enum-users

Script types: portrule
Categories: auth, intrusive
Download: http://nmap.org/svn/scripts/sip-enum-users.nse

User Summary
Enumerates a SIP server's valid extensions (users).
The script works by sending REGISTER SIP requests to the server with the specified extension and checking for the response status code in order to know if an extension is valid. If a response status code is 401 or 407, it means that the extension is valid and requires authentication. If the response status code is 200, it means that the extension exists and doesn't require any authentication while a 403 response status code means that extension exists but access is forbidden. To skip false positives, the script begins by sending a REGISTER request for a random extension and checking for response status code.

Script Arguments
sip-enum-users.users
If set, will also enumerate users from userslist file.
sip-enum-users.minext
Extension value to start enumeration from. Defaults to 0.
sip-enum-users.userslist
Path to list of users. Defaults to nselib/data/usernames.lst.
sip-enum-users.padding
Number of digits to pad zeroes up to. Defaults to 0. No padding if this is set to zero.
sip-enum-users.maxext
Extension value to end enumeration at. Defaults to 999.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
sip.timeout
See the documentation for the sip library.

Example Usage
nmap --script=sip-enum-users -sU -p 5060 <targets>
nmap --script=sip-enum-users -sU -p 5060 <targets> --script-args
'sip-enum-users.padding=4, sip-enum-users.minext=1000,
sip-enum-users.maxext=9999'

Default Option Used in script:
nmap -sV -sU -p 5060 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-5060[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="5060"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script sip-enum-users -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            sip(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script sip-enum-users -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            sip(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File sip-methods

Script types: portrule
Categories: default, safe, discovery
Download: http://nmap.org/svn/scripts/sip-methods.nse

User Summary
Enumerates a SIP Server's allowed methods (INVITE, OPTIONS, SUBSCRIBE, etc.)
The script works by sending an OPTION request to the server and checking for the value of the Allow header in the response.

Script Arguments
sip.timeout
See the documentation for the sip library.

Example Usage
nmap --script=sip-methods -sU -p 5060 <targets>

Default Option Used in script:
nmap -sV -sU -p 5060 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-5060[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="5060"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script sip-methods -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            sip(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script sip-methods -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            sip(host_ip,desc)
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