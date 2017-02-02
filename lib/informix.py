def informix(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for distributed compiler daemon distcc:
     [1] informix-brute
     [2] informix-query
     [3] informix-tables
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File informix-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/informix-brute.nse

User Summary
Performs brute force password auditing against IBM Informix Dynamic Server.

Script Arguments
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
informix.instance
See the documentation for the informix library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap --script informix-brute -p 9088 <host>

Default Option Used in script:
nmap -p 9088--script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-9088[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="9088"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script informix-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            informix(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script informix-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            informix(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File informix-query

Script types: portrule
Categories: intrusive, auth
Download: http://nmap.org/svn/scripts/informix-query.nse

User Summary
Runs a query against IBM Informix Dynamic Server using the given authentication credentials (see also: informix-query).

Script Arguments
informix-query.query
The query to run against the server (default: returns hostname and version)
informix-query.username
The username used for authentication
informix-query.database
The name of the database to connect to (default: sysmaster)
informix-query.instance
The name of the instance to connect to
informix-query.password
The password used for authentication
informix.instance
See the documentation for the informix library.

Example Usage
nmap -p 9088 <host> --script informix-query --script-args informix-query.username=informix,informix-query.password=informixte -p 9088 <host>

Default Option Used in script:
nmap -p 9088--script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-9088[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="9088"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script informix-query -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            informix(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script informix-query -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            informix(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File informix-tables

Script types: portrule
Categories: intrusive, auth
Download: http://nmap.org/svn/scripts/informix-tables.nse

User Summary
Retrieves a list of tables and column definitions for each database on an Informix server.

Script Arguments
informix-tables.username
The username used for authentication
informix-tables.password
The password used for authentication
Version 0.1 Created 27/07/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
informix.instance
See the documentation for the informix library.

Example Usage
nmap -p 9088 <host> --script informix-tables --script-args informix-tables.username=informix,informix-tables.password=informix

Default Option Used in script:
nmap -p 9088--script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-9088[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="9088"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script informix-tables -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            informix(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script informix-tables -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            informix(host_ip,desc)
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