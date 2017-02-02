def rsync(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for rsync remote file syncing protocol:
    \t[1] rsync-brute\n\t[2] rsync-list-modules\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rsync-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/rsync-brute.nse

User Summary
Performs brute force password auditing against the rsync remote file syncing protocol.

Script Arguments
rsync-brute.module
- the module against which brute forcing should be performed
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap -p 873 --script rsync-brute --script-args 'rsync-brute.module=www' <ip>

Default Option Used in script:
nmap -sV -p 873 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-873[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="873"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rsync-brute -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rsync(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rsync-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rsync(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rsync-list-modules

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/rsync-list-modules.nse

User Summary
Lists modules available for rsync (remote file sync) synchronization.

Example Usage
nmap -p 873 --script rsync-list-modules <ip> <ip>

Default Option Used in script:
nmap -sV -p 873 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-873[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="873"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rsync-list-modules -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rsync(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rsync-list-modules -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rsync(host_ip,desc)
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