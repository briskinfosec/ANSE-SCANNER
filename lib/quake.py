def quake(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Quake game servers:
    \t[1] quake1-info\n\t[2] quake3-info\n\t[3] quake3-master-getservers\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File quake1-info

Script types: portrule
Categories: default, discovery, safe, version
Download: http://nmap.org/svn/scripts/quake1-info.nse

User Summary
Extracts information from Quake game servers and other game servers which use the same protocol.
Quake uses UDP packets, which because of source spoofing can be used to amplify a denial-of-service attack. For each request, the script reports the payload amplification as a ratio. The format used is response_bytes/request_bytes=ratio
http://www.gamers.org/dEngine/quake/QDP/qnp.html

Example Usage
nmap -n -sU -Pn --script quake1-info -pU:26000-26004 -- <target>

Default Option Used in script:
nmap -n -Pn -sV -sU -pU:26000-26004 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-26000-26004[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="26000-26004 "
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -n -Pn -sV -sU --script quake1-info -pU:'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            quake(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script quake1-info -pU:'+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            quake(host_ip,desc)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File quake3-info

Script types: portrule
Categories: default, discovery, safe, version
Download: http://nmap.org/svn/scripts/quake3-info.nse

User Summary
Extracts information from a Quake3 game server and other games which use the same protocol.

Example Usage
nmap -sU -sV -Pn --script quake3-info.nse -p <port> <target>

Default Option Used in script:
nmap -Pn -sV -sU -p 27960 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-27960[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="27960"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -Pn -sV -sU   --script quake3-info -p:'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            quake(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script quake3-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            quake(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File quake3-master-getservers

Script types: portrule, postrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/quake3-master-getservers.nse

User Summary
Queries Quake3-style master servers for game servers (many games other than Quake 3 use this same protocol).

Script Arguments
quake3-master-getservers.outputlimit
If set, limits the amount of hosts returned by the script. All discovered hosts are still stored in the registry for other scripts to use. If set to 0 or less, all files are shown. The default value is 10.

Example Usage
nmap -sU -p 27950 --script=quake3-master-getservers <target>

Default Option Used in script:
nmap  -sV -sU -p 27950 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-27950[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="27960"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -Pn -sV -sU   --script quake3-info -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            quake(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script quake3-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            quake(host_ip,desc)
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