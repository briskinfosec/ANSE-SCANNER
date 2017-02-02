def freelacer(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Freelancer game server:
    [1]  freelancer-info
    [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File freelancer-info

Script types: portrule
Categories: default, discovery, safe, version
Download: http://nmap.org/svn/scripts/freelancer-info.nse

User Summary
Detects the Freelancer game server (FLServer.exe) service by sending a status query UDP probe.
When run as a version detection script (-sV), the script will report on the server name, current number of players,
maximum number of players, and whether it has a password set. When run explicitly (--script freelancer-info), the script
will additionally report on the server description, whether players can harm other players, and whether new players are allowed.
See http://sourceforge.net/projects/gameq/ (relevant files: games.ini, packets.ini, freelancer.php)

Example Usage
nmap -sU -sV -p 2302 <target>
nmap -sU -p 2302 --script=freelancer-info <target>

Default Option Used in script:
nmap -sU -sV -p 2302 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2302[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2302"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU -sV --script freelancer-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            freelacer(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sU -sV --script freelancer-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            freelacer(host_ip,desc)   
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