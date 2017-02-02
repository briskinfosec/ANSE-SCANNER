def mrinfo(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for multicast routing information:
      [1] mrinfo
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mrinfo

Script types: prerule
Categories: discovery, safe, broadcast
Download: http://nmap.org/svn/scripts/mrinfo.nse

User Summary
Queries targets for multicast routing information.
This works by sending a DVMRP Ask Neighbors 2 request to the target and listening for DVMRP Neighbors 2 responses that are
sent back and which contain local addresses and the multicast neighbors on each interface of the target. If no specific target is specified,
the request will be sent to the 224.0.0.1 All Hosts multicast address.
This script is similar somehow to the mrinfo utility included with Windows and Cisco IOS.

Script Arguments
mrinfo.target
Host to which the request is sent. If not set, the request will be sent to 224.0.0.1.
mrinfo.timeout
Time to wait for responses. Defaults to 5s.
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script mrinfo
nmap --script mrinfo -e eth1
nmap --script mrinfo --script-args 'mrinfo.target=172.16.0.4'

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script mrinfo'+' '+arg+' '+host_ip+' '+output,shell=True)
            mrinfo(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script mrinfo -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mrinfo(host_ip,desc)
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