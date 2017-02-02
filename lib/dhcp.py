def dhcp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for dhcp:
      [1] dhcp-discover
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dhcp-discover

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/dhcp-discover.nse

User Summary
Sends a DHCPINFORM request to a host on UDP port 67 to obtain all the local configuration parameters without all
locating a new address.

Some of the more useful fields:
    DHCP Server (the address of the server that responded)
    Subnet Mask
    Router
    DNS Servers
    Hostname

Script Arguments
randomize_mac
Set to true or 1 to send a random MAC address with the request (keep in mind that you may not see the response).
This should cause the router to reserve a new IP address each time.
requests
Set to an integer to make up to that many requests (and display the results).
dhcptype
The type of DHCP request to make. By default, DHCPINFORM is sent, but this argument can change it to DHCPOFFER,
DHCPREQUEST, DHCPDECLINE, DHCPACK, DHCPNAK, DHCPRELEASE or DHCPINFORM. Not all types will evoke a response from all
servers, and many require different fields to contain specific values.

Example Usage
nmap -sU -p 67 --script=dhcp-discover <target>

Default Option Used in script:
nmap -sU --script [script name] -p 67 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-67[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="67"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script dhcp-discover  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dhcp(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script dhcp-discover -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dhcp(host_ip,desc)
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