def fox(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Tridium Niagara Fox:
      [1] fox-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File fox-info

Script types: portrule
Categories: discovery, version
Download: http://nmap.org/svn/scripts/fox-info.nse

User Summary
Tridium Niagara Fox is a protocol used within Building Automation Systems. Based off Billy Rios and Terry McCorkle's
work this Nmap NSE will collect information from A Tridium Niagara system.

Example Usage
nmap --script fox-info.nse -p 1911 <host>

Default Option Used in script:
nmap -p 1911 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1911[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1911"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script fox-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            fox(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script fox-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            fox(host_ip,desc)   
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