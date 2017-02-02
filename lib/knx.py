def knx(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for KNX gateways:
     [1] knx-gateway-discove
     [2] knx-gateway-info
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File knx-gateway-discover

Script types: prerule
Categories: discovery, safe, broadcast
Download: http://nmap.org/svn/scripts/knx-gateway-discover.nse

User Summary
Discovers KNX gateways by sending a KNX Search Request to the multicast address 224.0.23.12 including a UDP payload with destination port 3671. KNX gateways will respond with a KNX Search Response including various information about the gateway, such as KNX address and supported services.
Further information: * DIN EN 13321-2 * http://www.knx.org/

Script Arguments
timeout
Max time to wait for a response. (default 3s)
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script knx-gateway-discover -e eth0

Default Option Used in script:
nmap -e [interface _name] --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your  interface name:")
            interface="-e"+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script knx-gateway-discover'+' '+interface+' '+arg+' '+host_ip+' '+output,shell=True)
            knx(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter=input("Enter your interface name:")
            interface="-e"+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script knx-gateway-discover -p '+' '+interface+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            knx(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File knx-gateway-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/knx-gateway-info.nse

User Summary
Identifies a KNX gateway on UDP port 3671 by sending a KNX Description Request.
Further information: * DIN EN 13321-2 * http://www.knx.org/

Example Usage
nmap -sV -sC <target>

Default Option Used in script:
nmap -e [interface_name] --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your interface name:")
            interface="-e"+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script knx-gateway-info'+' '+interface+' '+arg+' '+host_ip+' '+output,shell=True)
            knx(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter=input("Enter your interface name:")
            interface="-e"+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script knx-gateway-info -p '+' '+interface+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            knx(host_ip,desc)
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