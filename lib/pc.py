def pc(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for pcAnywhere remote access protocol:
    \t[1] pcanywhere-brute\n\t[2] pcworx-info\n\t[0]back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File pcanywhere-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/pcanywhere-brute.nse

User Summary
Performs brute force password auditing against the pcAnywhere remote access protocol.
Due to certain limitations of the protocol, bruteforcing is limited to single thread at a time.
After a valid login pair is guessed the script waits some time until server becomes available again.

Script Arguments
pcanywhere-brute.timeout
socket timeout for connecting to PCAnywhere (default 10s)
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap --script=pcanywhere-brute <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script pcanywhere-brute'+' '+arg+' '+host_ip+' '+output,shell=True)
            pc(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script pcanywhere-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            pc(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File pcworx-info

Script types: portrule
Categories: discovery
Download: http://nmap.org/svn/scripts/pcworx-info.nse

User Summary
This NSE script will query and parse pcworx protocol to a remote PLC. The script will send a initial request packets and once a response is received, it validates that it was a proper response to the command that was sent, and then will parse out the data. PCWorx is a protocol and Program by Phoenix Contact.
http://digitalbond.com

Example Usage
nmap --script pcworx-info -p 1962 <host>

Default Option Used in script:
nmap -sV -p 1962 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option(Recommended)-port-1962[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1962"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script pcworx-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            pc(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script pcworx-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            pc(host_ip,desc)
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