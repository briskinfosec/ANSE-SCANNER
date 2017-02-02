def backorifice(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Backorifice service
     [1] backorifice-brute
     [2] backorifice-info
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File backorifice-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/backorifice-brute.nse

User Summary
Performs brute force password auditing against the BackOrifice service. The backorifice-brute.ports script
zargument is mandatory (it specifies ports to run the script against).

Script Arguments
backorifice-brute.ports
(mandatory) List of UDP ports to run the script against separated with "," ex. "U:31337,25252,151-222", "U:1024-1512"
This script uses the brute library to perform password guessing. A successful password guess is stored in the nmap
registry, under the nmap.registry.credentials.backorifice table for other BackOrifice scripts to use.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly,
brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Default Option:
nmap -sU --script backorifice-brute <host> --script-args backorifice-brute.ports=<ports>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-31337 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="31337"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script backorifice-brute -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            backorifice(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script backorifice-brute -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            backorifice(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File backorifice-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/backorifice-info.nse

User Summary
Connects to a BackOrifice service and gathers information about the host and the BackOrifice service itself.
The extracted host information includes basic system setup, list of running processes, network resources and shares.
Information about the service includes enabled port redirections, listening console applications and a list of BackOrifice
plugins installed with the service.

Script Arguments
backorifice-info.seed
Encryption seed (default derived from password, or 31337 for no password).
backorifice-info.password
Encryption password (defaults to no password).

Example Usage
nmap --script backorifice-info <target> --script-args backorifice-info.password=<password>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-31337 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="31337"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script backorifice-info -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            backorifice(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script backorifice-info -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            backorifice(host_ip,desc)      
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