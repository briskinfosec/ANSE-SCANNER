def drda(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Informix, DB2 and Derby:
      [1] drda-brute
      [2] drda-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File drda-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/drda-brute.nse

User Summary
Performs password guessing against databases supporting the IBM DB2 protocol such as Informix, DB2 and Derby

Script Arguments
drda-brute.threads
the amount of accounts to attempt to brute force in parallel (default 10).
drda-brute.dbname
the database name against which to guess passwords (default "SAMPLE").
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap -p 50000 --script drda-brute <target>


Default Option Used in script:
nmap  -p 50000 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-50000[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="50000"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script drda-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            drda(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script drda-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            drda(host_ip,desc)  
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File drda-info

Script types: portrule
Categories: safe, discovery, version
Download: http://nmap.org/svn/scripts/drda-info.nse

User Summary
Attempts to extract information from database servers supporting the DRDA protocol. The script sends a
DRDA EXCSAT (exchange server attributes) command packet and parses the response.

Example Usage
nmap -sV <target>

Default Option Used in script:
nmap  -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script drda-info '+' '+arg+' '+host_ip+' '+output,shell=True)
            drda(host_ip,desc)     
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV--script drda-info-p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            drda(host_ip,desc)     
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