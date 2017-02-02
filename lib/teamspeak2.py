def teamspeak2(host_ip,desc) :
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for TeamSpeak 2 voice communication server:
    \t[1]teamspeak2-version\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File teamspeak2-version

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/teamspeak2-version.nse

User Summary
Detects the TeamSpeak 2 voice communication server and attempts to determine version and configuration information.
A single UDP packet (a login request) is sent. If the server does not have a password set, the exact version, name, and OS type will also be reported on.

Example Usage
nmap -sU -sV -p 8767 <target>

Default Option Used in script:
nmap  -sV -p 8767 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-8767[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8767"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  teamspeak2-version -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            teamspeak2(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  teamspeak2-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            teamspeak2(host_ip,desc) 
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