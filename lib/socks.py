def socks(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for socks servers:
    \t[1] socks-auth-info\n\t[2] socks-brute\n\t[3] socks-open-proxy\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File socks-auth-info

Script types: portrule
Categories: discovery, safe, default
Download: http://nmap.org/svn/scripts/socks-auth-info.nse

User Summary
Determines the supported authentication mechanisms of a remote SOCKS proxy server.
Starting with SOCKS version 5 socks servers may support authentication.
The script checks for the following authentication types: 0 - No authentication 1 - GSSAPI 2 - Username and password

Example Usage
nmap -p 1080 <ip> --script socks-auth-info

Default Option Used in script:
nmap  -sV -p 1080 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script socks-auth-info -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            socks(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script socks-auth-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            socks(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File socks-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/socks-brute.nse

User Summary
Performs brute force password auditing against SOCKS 5 proxy servers.

Script Arguments
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap --script socks-brute -p 1080 <host>

Default Option Used in script:
nmap  -sV -p 1080 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script socks-brute -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            socks(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script socks-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            socks(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File socks-open-proxy

Script types: portrule
Categories: default, discovery, external, safe
Download: http://nmap.org/svn/scripts/socks-open-proxy.nse

User Summary
Checks if an open socks proxy is running on the target.
The script attempts to connect to a proxy server and send socks4 and socks5 payloads. It is considered an open proxy if the script receives a Request Granted response from the target port.
The payloads try to open a connection to www.google.com port 80. A different test host can be passed as proxy.url argument.

Script Arguments
proxy.url
URL that will be requested to the proxy.
proxy.pattern
Pattern that will be searched inside the request results.

Example Usage
nmap --script=socks-open-proxy \
   --script-args proxy.url=<host>,proxy.pattern=<pattern>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script socks-open-proxy'+' '+arg+' '+host_ip+' '+output,shell=True)
            socks(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script socks-open-proxy -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            socks(host_ip,desc)
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