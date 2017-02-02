def IBMDB2(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for IBM DB2 Administration Server (DAS):
    [1] db2-das-info
    [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File db2-das-info

Script types: portrule
Categories: safe, discovery, version
Download: http://nmap.org/svn/scripts/db2-das-info.nse

User Summary
Connects to the IBM DB2 Administration Server (DAS) on TCP or UDP port 523 and exports the server profile.
No authentication is required for this request.
The script will also set the port product and version if a version scan is requested.

Example Usage
nmap -sV <target>

Default Option Used in script:
nmap --script [script name] -p 523 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-523[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="523"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script db2-das-info  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            IBMDB2(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sv --script db2-das-info -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            IBMDB2(host_ip,desc)      
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