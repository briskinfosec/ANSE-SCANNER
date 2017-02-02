def ndmp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Network Data Management Protocol (ndmp):
    \t[1] ndmp-fs-info\n\t[2] ndmp-version\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ndmp-fs-info

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ndmp-fs-info.nse

User Summary
Lists remote file systems by querying the remote device using the Network Data Management Protocol (ndmp).
NDMP is a protocol intended to transport data between a NAS device and the backup device, removing the need
for the data to pass through the backup server. The following products are known to support the protocol:
    Amanda
    Bacula
    CA Arcserve
    CommVault Simpana
    EMC Networker
    Hitachi Data Systems
    IBM Tivoli
    Quest Software Netvault Backup
    Symantec Netbackup
    Symantec Backup Exec

Example Usage
nmap -p 10000 --script ndmp-fs-info <ip>


Default Option Used in script:
nmap -sV -p 10000 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-10000[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="10000"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ndmp-fs-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ndmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ndmp-fs-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ndmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ndmp-version

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/ndmp-version.nse

User Summary
Retrieves version information from the remote Network Data Management Protocol (ndmp) service. NDMP is a protocol intended to transport data between a NAS device and the backup device, removing the need for the data to pass through the backup server. The following products are known to support the protocol:
    Amanda
    Bacula
    CA Arcserve
    CommVault Simpana
    EMC Networker
    Hitachi Data Systems
    IBM Tivoli
    Quest Software Netvault Backup
    Symantec Netbackup
    Symantec Backup Exec

Example Usage
nmap -sV <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ndmp-version'+' '+arg+' '+host_ip+' '+output,shell=True)
            ndmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ndmp-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ndmp(host_ip,desc)
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