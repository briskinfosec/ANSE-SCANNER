def ipv6(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for distributed compiler daemon distcc:
     [1] ipv6-multicast-mld-list
     [2] ipv6-node-info
     [3]  ipv6-ra-flood
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ipv6-multicast-mld-list

Script types: prerule
Categories: broadcast, discovery
Download: http://nmap.org/svn/scripts/ipv6-multicast-mld-list.nse

User Summary
Uses Multicast Listener Discovery to list the multicast addresses subscribed to by IPv6 multicast listeners on the link-local scope. Addresses in the IANA IPv6 Multicast Address Space Registry have their descriptions listed.

Script Arguments
ipv6-multicast-mld-list.timeout
timeout to wait for responses (default: 10s)
ipv6-multicast-mld-list.interface
Interface to send on (default: the interface specified with -e or every available Ethernet interface with an IPv6 address.)

Example Usage
nmap --script=ipv6-multicast-mld-list

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ipv6-multicast-mld-list'+' '+arg+' '+host_ip+' '+output,shell=True)
            ipv6(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ipv6-multicast-mld-list -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ipv6(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ipv6-node-info

Script types: hostrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/ipv6-node-info.nse

User Summary
Obtains hostnames, IPv4 and IPv6 addresses through IPv6 Node Information Queries.
IPv6 Node Information Queries are defined in RFC 4620. There are three useful types of queries:
    qtype=2: Node Name
    qtype=3: Node Addresses
    qtype=4: IPv4 Addresses
Some operating systems (Mac OS X and OpenBSD) return hostnames in response to qtype=4, IPv4 Addresses. In this case, the hostnames are still shown in the "IPv4 addresses" output row, but are prefixed by "(actually hostnames)".

Example Usage
nmap -6 <target>

Default Option Used in script:
nmap -6 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 --script ipv6-node-info'+' '+arg+' '+host_ip+' '+output,shell=True)
            ipv6(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 --script ipv6-node-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ipv6(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ipv6-ra-flood

Script types: prerule
Categories: dos, intrusive
Download: http://nmap.org/svn/scripts/ipv6-ra-flood.nse

User Summary
which have stateless autoconfiguration enabled by default (every major OS), will start to compute IPv6 suffix and update their routing table to reflect the accepted announcement. This will cause 100% CPU usage on Windows and platforms, preventing to process other application requests.
Vulnerable platforms:
    All Cisco IOS ASA with firmware < November 2010
    All Netscreen versions supporting IPv6
    Windows 2000/XP/2003/Vista/7/2008/8/2012
    All FreeBSD versions
    All NetBSD versions
    All Solaris/Illumos versions
Security advisory: http://www.mh-sec.de/downloads/mh-RA_flooding_CVE-2010-multiple.txt
WARNING: This script is dangerous and is very likely to bring down a server or network appliance. It should not be run in a production environment unless you (and, more importantly, the business) understand the risks!
Additional documents: https://tools.ietf.org/rfc/rfc6104.txt

Script Arguments
ipv6-ra-flood.interface
defines interface we should broadcast on
ipv6-ra-flood.timeout
runs the script until the timeout is reached (default: 30s). If timeout is zero, the script will run forever.

Example Usage
nmap -6 --script ipv6-ra-flood.nse
nmap -6 --script ipv6-ra-flood.nse --script-args 'interface=<interface>'
nmap -6 --script ipv6-ra-flood.nse --script-args 'interface=<interface>,timeout=10s'

Default Option Used in script:
nmap -6 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 --script ipv6-ra-flood'+' '+arg+' '+host_ip+' '+output,shell=True)
            ipv6(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -6 --script ipv6-ra-flood -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ipv6(host_ip,desc)
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