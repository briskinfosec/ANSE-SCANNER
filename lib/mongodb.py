def mongodb(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for mongodb:
      [1] mongodb-brute
      [2] mongodb-databases
      [3] mongodb-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mongodb-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/mongodb-brute.nse

User Summary
Performs brute force password auditing against the MongoDB database.

Script Arguments
mongodb-brute.db
Database against which to check. Default: admin
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
mongodb.db
See the documentation for the mongodb library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap -p 27017 <ip> --script mongodb-brute <host>

Default Option Used in script:
nmap  -p  27017  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-27017[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="27017"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mongodb-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mongodb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mongodb-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mongodb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mongodb-databases

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/mongodb-databases.nse
User Summary

Attempts to get a list of tables from a MongoDB database.
Script Arguments

mongodb.db
See the documentation for the mongodb library.
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -p 27017 --script mongodb-databases <host>

Default Option Used in script:
nmap  -p  27017  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-27017[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="27017"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mongodb-databases -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mongodb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mongodb-databases -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mongodb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mongodb-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/mongodb-info.nse

User Summary
Attempts to get build info and server status from a MongoDB database.

Script Arguments
mongodb-info.db
Database to check. Default: admin
mongodb.db
See the documentation for the mongodb library.
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -p 27017 --script mongodb-info <host>

Default Option Used in script:
nmap  -p  27017  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-27017[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="27017"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mongodb-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mongodb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mongodb-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mongodb(host_ip,desc)
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