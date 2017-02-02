def nje(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for dz/OS JES Network Job Entry (NJE):
    \t[1] nje-node-brute\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File nje-node-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/nje-node-brute.nse

User Summary
z/OS JES Network Job Entry (NJE) target node name brute force.
NJE node communication is made up of an OHOST and an RHOST. Both fields must be present when conducting the handshake.
This script attemtps to determine the target systems NJE node name.
To initiate NJE the client sends a 33 byte record containing the type of record, the hostname (RHOST), IP address (RIP),
target (OHOST), target IP (OIP) and a 1 byte response value (R) as outlined below:

Script Arguments
nje-node-brute.hostlist
The filename of a list of node names to try. Defaults to "nselib/data/vhosts-default.lst"
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap -sV --script=nje-node-brute <target>
nmap --script=nje-node-brute --script-args=hostlist=nje_names.txt -p 175 <target>

Default Option Used in script:
nmap -sV -p 175 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-175[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="175"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script nje-node-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nje(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script nje-node-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nje(host_ip,desc)
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