def rpcap(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for WinPcap Remote Capture Daemon (rpcap):
    \t[1] rpcap-brute\n\t[2] rpcap-info\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rpcap-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/rpcap-brute.nse
User Summary

Performs brute force password auditing against the WinPcap Remote Capture Daemon (rpcap).
Script Arguments

brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap -p 2002 <ip> --script rpcap-brute


Default Option Used in script:
nmap -sV -p 2002 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2022[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2022"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rpcap-brute -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rpcap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rpcap-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rpcap(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rpcap-info

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/rpcap-info.nse

User Summary
Connects to the rpcap service (provides remote sniffing capabilities through WinPcap) and retrieves interface information. The service can either be setup to require authentication or not and also supports IP restrictions.

Script Arguments
creds.rpcap
username:password to use for authentication
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -p 2002 <ip> --script rpcap-info
nmap -p 2002 <ip> --script rpcap-info --script-args="creds.rpcap='administrator:foobar'"


Default Option Used in script:
nmap -sV -p 2002 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2022[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2022"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rpcap-info -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rpcap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rpcap-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rpcap(host_ip,desc)
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