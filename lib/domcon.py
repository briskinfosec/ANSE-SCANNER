def domcon(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Lotus Domino Console :
     [1] domcon-brute
     [2] domcon-cmd
     [3] domino-enum-users
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File domcon-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/domcon-brute.nse
User Summary

Performs brute force password auditing against the Lotus Domino Console.

Script Arguments
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly,
brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap --script domcon-brute -p 2050 <host>

Default Option Used in script:
nmap  -p 2050 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2050[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2050"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script domcon-brute  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            domcon(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script domcon-brute  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            domcon(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File domcon-cmd

Script types: portrule
Categories: intrusive, auth
Download: http://nmap.org/svn/scripts/domcon-cmd.nse

User Summary
Runs a console command on the Lotus Domino Console using the given authentication credentials

Script Arguments
domcon-cmd.cmd
The command to run on the remote server
domcon-cmd.pass
The password used to authenticate to the server
domcon-cmd.user
The user used to authenticate to the server

Example Usage
nmap -p 2050 <host> --script domcon-cmd --script-args domcon-cmd.cmd="show server", \
  domcon-cmd.user="Patrik Karlsson",domcon-cmd.pass="secret"


Default Option Used in script:
nmap  -p 2050 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2050[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2050"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script domcon-cmd -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            domcon(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script domcon-cmd -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            domcon(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File domino-enum-users

Script types: portrule
Categories: intrusive, auth
Download: http://nmap.org/svn/scripts/domino-enum-users.nse

User Summary
Attempts to discover valid IBM Lotus Domino users and download their ID files by exploiting the
CVE-2006-5835 vulnerability.

Script Arguments
domino-id.path
the location to which any retrieved ID files are stored
domino-id.username
the name of the user from which to retrieve the ID. If this parameter is not specified, the unpwdb library
will be usedto brute force names of users.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap --script domino-enum-users -p 1352 <host>"

Default Option Used in script:
nmap  -p 1352 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1352[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1352"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script domcon-cmd -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            domcon(host_ip,desc)     
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script domcon-cmd -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            domcon(host_ip,desc)      
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