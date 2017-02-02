def ipmi(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for IPMI RPC server:
     [1] ipmi-brute
     [2] ipmi-cipher-zero
     [3] ipmi-version
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ipmi-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/ipmi-brute.nse

User Summary
Performs brute force password auditing against IPMI RPC server.

Script Arguments
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap -sU --script ipmi-brute -p 623 <host>


Default Option Used in script:
nmap -p 623--script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-623[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="623"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script ipmi-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ipmi(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script ipmi-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ipmi(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ipmi-cipher-zero

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/ipmi-cipher-zero.nse

User Summary
IPMI 2.0 Cipher Zero Authentication Bypass Scanner. This module identifies IPMI 2.0 compatible systems that are vulnerable to an authentication bypass vulnerability through the use of cipher zero.

Script Arguments
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sU --script ipmi-cipher-zero -p 623 <host>

Default Option Used in script:
nmap -p 623 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-623[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="623"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script ipmi-cipher-zero -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ipmi(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script ipmi-cipher-zero -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ipmi(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ipmi-version

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ipmi-version.nse

User Summary
Performs IPMI Information Discovery through Channel Auth probes.

Example Usage
nmap -sU --script ipmi-version -p 623 <host>

Default Option Used in script:
nmap -sU -p 623  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-623[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="623"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script ipmi-version -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ipmi(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script ipmi-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ipmi(host_ip,desc)
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