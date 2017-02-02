def dict(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for DICT protocol:
    [1] dict-info
    [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dict-info

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/dict-info.nse

User Summary
Connects to a dictionary server using the DICT protocol, runs the SHOW SERVER command,
and displays the result.
The SHOW server command must be implemented and depending on access will show server information and accessible databases.
If authentication is required, the list of databases will not be shown.

Example Usage
nmap -p 2628 <ip> --script dict-info

Default Option Used in script:
nmap  --script [script name] -p 2628 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2628[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2628"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script dict-info  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dict(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script dict-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dict(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "0":
        from ANSE import service_scan
        service_scan(host_ip,desc)
    else:
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)         