def cassandra_db(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Cassandra database
      [1] cassandra-brute
      [2] cassandra-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File cassandra-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/cassandra-brute.nse

User Summary
Performs brute force password auditing against the Cassandra database.
For more information about Cassandra, see: http://cassandra.apache.org/

Script Arguments
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly,
brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap -p 9160 <ip> --script=cassandra-brute

Default Option Used in script:
nmap --script [script name] -p 9160 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option port-9160[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="9160"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script cassandra-brute '+default_port+' '+arg+' '+output,shell=True)
            cassandra_db(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script cassandra-brute -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            cassandra_db(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File cassandra-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/cassandra-info.nse

User Summary
Attempts to get basic info and server status from a Cassandra database.
For more information about Cassandra, see: http://cassandra.apache.org/
Script Arguments
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -p 9160 <ip> --script=cassandra-info

Default Option Used in script:
nmap -p 9160--script [script name]   [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-9160 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="9160"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script cassandra-info '+default_port+' '+arg+' '+output,shell=True)
            cassandra_db(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script cassandra-info -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            cassandra_db(host_ip,desc)      
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