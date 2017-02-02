def ike(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for IKE service:
      [1] ike-version
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
_
File ike-version

Script types: portrule
Categories: default, discovery, safe, version
Download: http://nmap.org/svn/scripts/ike-version.nse

User Summary
Obtains information (such as vendor and device type where available) from an IKE service by sending four packets to the host. This scripts tests with both Main and Aggressive Mode and sends multiple transforms per request.

Example Usage
nmap -sU -sV -p 500 <target>
nmap -sU -p 500 --script ike-version <target>

Default Option Used in script:
nmap -sU -sV -p 500 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-500[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="500"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU -sV --script ike-version -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ike(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU -sV --script ike-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ike(host_ip,desc)
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