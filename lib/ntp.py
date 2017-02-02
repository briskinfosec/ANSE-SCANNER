def ntp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for NTP server:
    \t[1] ntp-info\n\t[2] ntp-monlistsssss\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ntp-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/ntp-info.nse

User Summary
Gets the time and configuration variables from an NTP server. We send two requests: a time request and a "read variables" (opcode 2) control message. Without verbosity, the script shows the time and the value of the version, processor, system, refid, and stratum variables. With verbosity, all variables are shown.
See RFC 1035 and the Network Time Protocol Version 4 Reference and Implementation Guide (http://www.eecis.udel.edu/~mills/database/reports/ntp4/ntp4.pdf) for documentation of the protocol.

Example Usage
nmap -sU -p 123 --script ntp-info <target>


Default Option Used in script:
nmap -sV -sU 5666 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-123[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="123"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script ntp-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ntp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ntp-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ntp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg) 
        
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ntp-monlist

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/ntp-monlist.nse

User Summary
Obtains and prints an NTP server's monitor data.
Monitor data is a list of the most recently used (MRU) having NTP associations with the target. Each record contains information about the most recent NTP packet sent by a host to the target including the source and destination addresses and the NTP version and mode of the packet. With this information it is possible to classify associated hosts as Servers, Peers, and Clients.
A Peers command is also sent to the target and the peers list in the response allows differentiation between configured Mode 1 Peers and clients which act like Peers (such as the Windows W32Time service).
Associated hosts are further classified as either public or private. Private hosts are those having IP addresses which are not routable on the public Internet and thus can help to form a picture about the topology of the private network on which the target resides.
Other information revealed by the monlist and peers commands are the host with which the target clock is synchronized and hosts which send Control Mode (6) and Private Mode (7) commands to the target and which may be used by admins for the NTP service.
It should be noted that the very nature of the NTP monitor data means that the Mode 7 commands sent by this script are recorded by the target (and will often appear in these results). Since the monitor data is a MRU list, it is probable that you can overwrite the record of the Mode 7 command by sending an innocuous looking Client Mode request. This can be achieved easily using Nmap: nmap -sU -pU:123 -Pn -n --max-retries=0 <target>

Notes:
    The monitor list in response to the monlist command is limited to 600 associations.
    The monitor capability may not be enabled on the target in which case you may receive an error number 4 (No Data Available).
    There may be a restriction on who can perform Mode 7 commands (e.g. "restrict noquery" in ntp.conf) in which case you may not receive a reply.
    This script does not handle authenticating and targets expecting auth info may respond with error number 3 (Format Error).

Example Usage
nmap -sU -pU:123 -Pn -n --script=ntp-monlist <target>

Default Option Used in script:
nmap -Pn -n -sV -pU 123 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-123[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="123"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -Pn -n -sV --script ntp-monlist -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ntp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ntp-monlist -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ntp(host_ip,desc)
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