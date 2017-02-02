def nbstat(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for NetBIOS:
    \t[1] nbstat\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File nbstat

Script types: hostrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/nbstat.nse

User Summary
Attempts to retrieve the target's NetBIOS names and MAC address.
By default, the script displays the name of the computer and the logged-in user; if the verbosity is turned up, it displays
all names the system thinks it owns.

Example Usage
sudo nmap -sU --script nbstat.nse -p137 <host>


Default Option Used in script:
nmap  -sU -p 137 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-137[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="137"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script nbstat -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nbstat(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script nbstat -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nbstat(host_ip,desc)
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