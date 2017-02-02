def multihomed(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for multihomed systems:
    \t[1] duplicates \n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File duplicates

Script types:
Categories: safe
Download: http://nmap.org/svn/scripts/duplicates.nse

User Summary
Attempts to discover multihomed systems by analysing and comparing information collected by other scripts.
The information analyzed currently includes, SSL certificates, SSH host keys, MAC addresses, and Netbios server names.
In order for the script to be able to analyze the data it has dependencies to the following scripts: ssl-cert,ssh-hostkey,nbtstat.
One or more of these scripts have to be run in order to allow the duplicates script to analyze the data.

Example Usage
sudo nmap -PN -p445,443 --script duplicates,nbstat,ssl-cert <ips>

Default Option Used in script:
nmap -PN -p445,443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445,443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445,443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -PN --script duplicates,nbstat,ssl-cert  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            multihomed(host_ip,desc)   
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -PN --script duplicates,nbstat,ssl-cert  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            multihomed(host_ip,desc)    
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