def ataoe(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for  ATA over Ethernet protocol
      [1] broadcast-ataoe-discover
      [2] broadcast-avahi-dos
      [3] broadcast-bjnp-discover
      [4] broadcast-db2-discover
      [5] broadcast-dhcp-discover
      [6] broadcast-dhcp6-discover
      [7] broadcast-dns-service-discovery
      [8] broadcast-dropbox-listener
      [9] broadcast-eigrp-discovery
     [10] broadcast-igmp-discovery
     [11] broadcast-listener
     [12] broadcast-ms-sql-discover
     [13] broadcast-netbios-master-browser
     [14] broadcast-networker-discover
     [15] broadcast-novell-locate
     [16] broadcast-pc-anywhere
     [17] broadcast-pc-duo
     [18] broadcast-pim-discovery
     [19] broadcast-ping
     [20] broadcast-pppoe-discover
     [21] broadcast-rip-discover
     [22] broadcast-ripng-discover
     [23] broadcast-sonicwall-discover
     [24] broadcast-sybase-asa-discover
     [25] broadcast-upnp-info
     [26] broadcast-versant-locate
     [27] broadcast-wake-on-lan
     [28] broadcast-wpad-discover
     [29] broadcast-wsdd-discover
     [30] broadcast-xdmcp-discover
     [31] broadcast-tellstick-discover
     [0]  back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-ataoe-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-ataoe-discover.nse

User Summary
Discovers servers supporting the ATA over Ethernet protocol. ATA over Ethernet is an ethernet protocol developed by the Brantley Coile Company and allows for simple, high-performance access to SATA drives over Ethernet.
Discovery is performed by sending a Query Config Request to the Ethernet broadcast address with all bits set in the major and minor fields of the header.

Example Usage
nmap --script broadcast-ataoe-discover -e <interface>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option[Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter Your Interface name:")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-ataoe-discover '+interface+' '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter = input("Enter Your Interface name:")
            interface = "-e" + ' ' + inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-ataoe-discover -p '+custom_port+' '+interface+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-avahi-dos

Script types: prerule
Categories: broadcast, dos, intrusive, vuln
Download: http://nmap.org/svn/scripts/broadcast-avahi-dos.nse

User Summary
Attempts to discover hosts in the local network using the DNS Service Discovery protocol and sends a NULL UDP
packet to each host to test if it is vulnerable to the Avahi NULL UDP packet denial of service (CVE-2011-1002).
The broadcast-avahi-dos.wait script argument specifies how many number of seconds to wait before a new attempt
of host discovery. Each host who does not respond to this second attempt will be considered vulnerable.

Reference:
    http://avahi.org/ticket/325
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1002

Script Arguments
broadcast-avahi-dos.wait
Wait time in seconds before executing the check, the default value is 20 seconds.
max-newtargets, newtargets
See the documentation for the target library.
dnssd.services
See the documentation for the dnssd library.
Example Usage
nmap --script=broadcast-avahi-dos

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-avahi-dos '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script broadcast-avahi-dos -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-bjnp-discover

Script types: prerule
Categories: safe, broadcast
Download: http://nmap.org/svn/scripts/broadcast-bjnp-discover.nse

User Summary
Attempts to discover Canon devices (Printers/Scanners) supporting the BJNP protocol by sending BJNP Discover requests
to the network broadcast address for both ports associated with the protocol.
The script then attempts to retrieve the model, version and some additional information for all discovered devices.

Script Arguments
broadcast-bjnp-discover.timeout
specifies the amount of seconds to sniff the network interface. (default 30s)

Example Usage
nmap --script broadcast-bjnp-discover

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-bjnp-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-bjnp-discover -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-db2-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-db2-discover.nse
User Summary

Attempts to discover DB2 servers on the network by sending a broadcast request to port 523/udp.
Script Arguments

max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script db2-discover

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script db2-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script db2-discover -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-dhcp-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-dhcp-discover.nse

User Summary
Sends a DHCP request to the broadcast address (255.255.255.255) and reports the results. The script uses a static MAC address
(DE:AD:CO:DE:CA:FE) while doing so in order to prevent scope exhaustion.
The script reads the response using pcap by opening a listening pcap socket on all available ethernet interfaces that are reported up. If no response has been received before the timeout has been reached (default 10 seconds) the script will abort execution.
The script needs to be run as a privileged user, typically root.

Script Arguments
broadcast-dhcp-discover.timeout
time in seconds to wait for a response (default: 10s)
Example Usage
sudo nmap --script broadcast-dhcp-discov

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-dhcp-discov '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-dhcp-discov -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-dhcp6-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-dhcp6-discover.nse
User Summary

Sends a DHCPv6 request (Solicit) to the DHCPv6 multicast address, parses the response, then extracts and prints the address along with any options returned by the server.

The script requires Nmap to be run in privileged mode as it binds the socket to a privileged port (udp/546).
Example Usage

nmap -6 --script broadcast-dhcp6-discover

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Options [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script abroadcast-dhcp6-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script broadcast-dhcp6-discover -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-dns-service-discovery

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-dns-service-discovery.nse
User Summary

Attempts to discover hosts' services using the DNS Service Discovery protocol. It sends a multicast DNS-SD query and collects all the responses.

The script first sends a query for _services._dns-sd._udp.local to get a list of services. It then sends a followup query for each one to try to get more information.
Script Arguments

max-newtargets, newtargets
See the documentation for the target library.
dnssd.services
See the documentation for the dnssd library.

Example Usage
nmap --script=broadcast-dns-service-discovery

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Options [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-dns-service-discovery '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-dns-service-discovery -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-dropbox-listener

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-dropbox-listener.nse

User Summary
Listens for the LAN sync information broadcasts that the Dropbox.com client broadcasts every 20 seconds, then prints all the discovered client IP addresses, port numbers, version numbers, display names, and more.
If the newtargets script argument is given, all discovered Dropbox clients will be added to the Nmap target list rather than just listed in the output.

Script Arguments
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script=broadcast-dropbox-listener
nmap --script=broadcast-dropbox-listener --script-args=newtargets -Pn

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-dropbox-listener '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script broadcast-d ropbox-listener -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-eigrp-discovery

Script types: prerule
Categories: discovery, broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-eigrp-discovery.nse

User Summary
Performs network discovery and routing information gathering through Cisco's Enhanced Interior Gateway Routing Protocol (EIGRP).
The script works by sending an EIGRP Hello packet with the specified Autonomous System value to the 224.0.0.10 multicast address
and listening for EIGRP Update packets. The script then parses the update responses for routing information.
If no A.S value was provided by the user, the script will listen for multicast Hello packets to grab an A.S value. If no interface
was provided as a script argument or through the -e option, the script will send packets and listen through all valid ethernet interfaces
simultaneously.

Script Arguments
broadcast-eigrp-discovery.kparams
the K metrics. Defaults to 101000.
broadcast-eigrp-discovery.as
Autonomous System value to announce on. If not set, the script will listen for announcements on 224.0.0.10 to grab an A.S value.
broadcast-eigrp-discovery.interface
Interface to send on (overrides -e)
broadcast-eigrp-discovery.timeout
Max amount of time to listen for A.S announcements and updates. Defaults to 10 seconds.
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script=broadcast-eigrp-discovery <targets>
nmap --script=broadcast-eigrp-discovery <targets> -e wlan0

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your Interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-eigrp-discovery '+interface+' '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            inter=input("Enter your Interface name")
            interface="-e"+' '+inter
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-eigrp-discovery -p '+custom_port+' '+arg+' '+interface+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "10":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-igmp-discovery

Script types: prerule
Categories: discovery, safe, broadcast
Download: http://nmap.org/svn/scripts/broadcast-igmp-discovery.nse
User Summary

Discovers targets that have IGMP Multicast memberships and grabs interesting information.
The scripts works by sending IGMP Membership Query message to the 224.0.0.1 All Hosts multicast address and listening for
IGMP Membership Report messages. The script then extracts all the interesting information from the report messages such as
the version, group, mode, source addresses (depending on the version).
The script defaults to sending an IGMPv2 Query but this could be changed to another version (version 1 or 3) or to sending
queries of all three version. If no interface was specified as a script argument or with the -e option, the script will proceed
o sending queries through all the valid ethernet interfaces.

Script Arguments
broadcast-igmp-discovery.mgroupnamesdb
Database with multicast group names
broadcast-igmp-discovery.version
IGMP version to use. Could be 1, 2, 3 or all. Defaults to 2
broadcast-igmp-discovery.timeout
Time to wait for reports in seconds. Defaults to 5 seconds.
broadcast-igmp-discovery.interface

Network interface to use.
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script broadcast-igmp-discovery
nmap --script broadcast-igmp-discovery -e wlan0
nmap --script broadcast-igmp-discovery
--script-args 'broadcast-igmp-discovery.version=all, broadcast-igmp-discovery.timeout=3'

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your Interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-igmp-discovery '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            inter=input("Enter your Interface name")
            interface="-e"+' '+inter
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-igmp-discovery  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "11":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-listener

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-listener.nse

User Summary
Sniffs the network for incoming broadcast communication and attempts to decode the received packets. It supports protocols
like CDP, HSRP, Spotify, DropBox, DHCP, ARP and a few more. See packetdecoders.lua for more information.
The script attempts to sniff all ethernet based interfaces with an IPv4 address unless a specific interface was given using
the -e argument to Nmap.

Script Arguments
broadcast-listener.timeout
specifies the amount of seconds to sniff the network interface. (default 30s)
The script attempts to discover all available ipv4 network interfaces, unless the Nmap -e argument has been supplied, and
then starts sniffing packets on all of the discovered interfaces. It sets a BPF filter to exclude all packets that have the
interface address as source or destination in order to capture broadcast traffic.
Incoming packets can either be either layer 3 (usually UDP) or layer 2. Depending on the layer the packet is matched against a packet decoder loaded from the external nselib/data/packetdecoder.lua file. A more detailed description on how the decoders work can be found in that file. In short, there are two different types of decoders: udp and ether. The udp decoders get triggered by the destination port number, while the ether decoders are triggered by a pattern match. The port or pattern is used as an index in a table containing functions to process packets and fetch the decoded results.
Example Usage
nmap --script broadcast-listener
nmap --script broadcast-listener -e eth0

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option[Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your Interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-listener '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            inter=input("Enter your Interface name")
            interface="-e"+' '+inter
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-listener -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "12":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-ms-sql-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-ms-sql-discover.nse

User Summary
Discovers Microsoft SQL servers in the same broadcast domain.
QL Server credentials required: No (will not benefit from mssql.username & mssql.password).
Nmap registry for use by any other ms-sql-* scripts that are run in the same scan.
In contrast to the ms-sql-discover script, the broadcast version will use a broadcast method rather than targeting
individual hosts. However, the broadcast version will only use the SQL Server Browser service discovery method.

Script Arguments
max-newtargets, newtargets
See the documentation for the target library.
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol,
mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script broadcast-ms-sql-discover
nmap --script broadcast-ms-sql-discover,ms-sql-info --script-args=newtargets

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-ms-sql-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-ms-sql-discover -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "13":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-netbios-master-browser

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-netbios-master-browser.nse
User Summary

Attempts to discover master browsers and the domains they manage.
Example Usage
nmap --script=broadcast-netbios-master-browser

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script netbios-master-browser '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script netbios-master-browser -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "14":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-networker-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-networker-discover.nse

User Summary
Discovers EMC Networker backup software servers on a LAN by sending a network broadcast query.

Script Arguments
mount.version, nfs.version, rpc.protocol
See the documentation for the rpc library.

Example Usage
nmap --script broadcast-networker-discover

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script broadcast-networker-discover '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-networker-discover -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "15":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-novell-locate

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-novell-locate.nse

User Summary
Attempts to use the Service Location Protocol to discover Novell NetWare Core Protocol (NCP) servers.

Example Usage
nmap -sV --script=broadcast-novell-locate <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]_________________________________
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-novell-locate  '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-novell-locate -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "16":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-pc-anywhere

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-pc-anywhere.nse

User Summary
Sends a special broadcast probe to discover PC-Anywhere hosts running on a LAN.
Script Arguments
broadcast-pc-anywhere.timeout
specifies the amount of seconds to sniff the network interface. (default varies according to timing. -T3 = 5s)
Example Usage
nmap --script broadcast-pc-anywhere

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-pc-anywhere '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-pc-anywhere -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "17":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-pc-duo

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-pc-duo.nse

User Summary
Discovers PC-DUO remote control hosts and gateways running on a LAN by sending a special broadcast UDP probe.

Script Arguments
broadcast-pc-duo.timeout
specifies the amount of seconds to sniff the network interface. (default varies according to timing. -T3 = 5s)
Example Usage
nmap --script broadcast-pc-duo

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script broadcast-pc-duo '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-pc-duo-p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "18":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-pim-discovery

Script types: prerule
Categories: discovery, safe, broadcast
Download: http://nmap.org/svn/scripts/broadcast-pim-discovery.nse

User Summary
Discovers routers that are running PIM (Protocol Independent Multicast).
This works by sending a PIM Hello message to the PIM multicast address 224.0.0.13 and listening for Hello messages from other routers.

Script Arguments
broadcast-pim-discovery.timeout
Time to wait for responses in seconds. Defaults to 5s.
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script broadcast-pim-discovery
nmap --script broadcast-pim-discovery -e eth1
 --script-args 'broadcast-pim-discovery.timeout=10'

Default Option Used in script:
nmap -script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter Your Interface name:")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-pim-discovery '+interface+' '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            inter=input("Enter Your Interface name:")
            interface="-e"+' '+inter
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-pim-discovery -p '+custom_port+' '+interface+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "19":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-ping

Script types: prerule
Categories: discovery, safe, broadcast
Download: http://nmap.org/svn/scripts/broadcast-ping.nse

User Summary
Sends broadcast pings on a selected interface using raw ethernet packets and outputs the responding hosts' IP and
MAC addresses or (if requested) adds them as targets. Root privileges on UNIX are required to run this script since
it uses raw sockets. Most operating systems don't respond to broadcast-ping probes, but they can be configured to do so.
The interface on which is broadcasted can be specified using the -e Nmap option or the broadcast-ping.interface script-arg.
If no interface is specified this script broadcasts on all ethernet interfaces which have an IPv4 address defined.
The newtarget script-arg can be used so the script adds the discovered IPs as targets.
The timeout of the ICMP probes can be specified using the timeout script-arg. The default timeout is 3000 ms. A higher number
might be necessary when scanning across larger networks.
The number of sent probes can be specified using the num-probes script-arg. The default number is 1. A higher value might
get more results on larger networks.
The ICMP probes sent comply with the --ttl and --data-length Nmap options, so you can use those to control the TTL(time to live)
and ICMP payload length respectively. The default value for TTL is 64, and the length of the payload is 0. The payload is consisted of random bytes.

Script Arguments
broadcast-ping.timeout
timespec specifying how long to wait for response (default 3s)
broadcast-ping.num_probes
number specifying how many ICMP probes should be sent (default 1)
broadcast-ping.interface
string specifying which interface to use for this script (default all interfaces)
max-newtargets, newtargets
See the documentation for the target library.
Example Usage
nmap -e <interface> [--ttl <ttl>] [--data-length <payload_length>]
--script broadcast-ping [--script-args [broadcast-ping.timeout=<ms>],[num-probes=<n>]

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter Your Interface name:")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script auth-spoof '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script auth-spoof -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "20":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-pppoe-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-pppoe-discover.nse

User Summary
Discovers PPPoE (Point-to-Point Protocol over Ethernet) servers using the PPPoE Discovery protocol (PPPoED). PPPoE is
an ethernet based protocol so the script has to know what ethernet interface to use for discovery. If no interface is specified,
requests are sent out on all available interfaces.
As the script send raw ethernet frames it requires Nmap to be run in privileged mode to operate.
Example Usage

nmap --script broadcast-pppoe-discover

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-pppoe-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-pppoe-discover -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "21":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-rip-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-rip-discover.nse

User Summary
Discovers hosts and routing information from devices running RIPv2 on the LAN. It does so by sending a RIPv2 Request
command and collects the responses from all devices responding to the request.

Script Arguments
broadcast-rip-discover.timeout
timespec defining how long to wait for a response. (default 5s)

Example Usage
nmap --script broadcast-rip-discover\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-rip-discover '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-rip-discover -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "22":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-ripng-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-ripng-discover.nse

User Summary
Discovers hosts and routing information from devices running RIPng on the LAN by sending a broadcast RIPng Request
command and collecting any responses.

Script Arguments
broadcast-ripng-discover.timeout
sets the connection timeout (default: 5s)

Example Usage
nmap --script broadcast-ripng-discover\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap ---script broadcast-ripng-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-ripng-discover  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "23":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-sonicwall-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-sonicwall-discover.nse

User Summary
Discovers Sonicwall firewalls which are directly attached (not routed) using the same method as the manufacturers own 'SetupTool'.
An interface needs to be configured, as the script broadcasts a UDP packet.
The script needs to be run as a privileged user, typically root.

References:

    https://support.software.dell.com/kb/sw3677)

Script Arguments
broadcast-sonicwall-discover.timeout
time in seconds to wait for a response (default: 1s)
max-newtargets, newtargets
See the documentation for the target library.
Example Usage
nmap -e eth0 --script broadcast-sonicwall-discover

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your Interface name:" )
            interface="-e" +' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -script broadcast-sonicwall-discover '+interface+' '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter = input("Enter your Interface name:")
            interface = "-e" + ' ' + inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -script broadcast-sonicwall-discover -p '+custom_port+' '+interface+' '++arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "24":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-sybase-asa-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-sybase-asa-discover.nse

User Summary
Discovers Sybase Anywhere servers on the LAN by sending broadcast discovery messages.
Example Usage
nmap --script broadcast-sybase-asa-discover

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap ---script broadcast-sybase-asa-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script broadcast-sybase-asa-discover -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "25":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-upnp-info

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-upnp-info.nse
User Summary

Attempts to extract system information from the UPnP service by sending a multicast query, then collecting, parsing, and displaying all responses.
Script Arguments

slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
max-newtargets, newtargets
See the documentation for the target library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV --script=broadcast-upnp-info <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-upnp-info '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-upnp-info  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "26":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-versant-locate

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-versant-locate.nse

User Summary
Discovers Versant object databases using the broadcast srvloc protocol.
Example Usage
nmap --script broadcast-versant-locate

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-versant-locate '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-versant-locate -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "27":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-wake-on-lan

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-wake-on-lan.nse

User Summary
Wakes a remote system up from sleep by sending a Wake-On-Lan packet.

Script Arguments
broadcast-wake-on-lan.address
The broadcast address to which the WoL packet is sent.
broadcast-wake-on-lan.MAC
The MAC address of the remote system to wake up

Example Usage
nmap --script broadcast-wake-on-lan --script-args broadcast-wake-on-lan.MAC='00:12:34:56:78:9A'

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-wake-on-lan '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script broadcast-wake-on-lan -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "28":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-wpad-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-wpad-discover.nse
User Summary

Retrieves a list of proxy servers on a LAN using the Web Proxy Autodiscovery Protocol (WPAD). It implements both the DHCP and DNS methods of doing so and starts by querying DHCP to get the address. DHCP discovery requires nmap to be running in privileged mode and will be skipped when this is not the case. DNS discovery relies on the script being able to resolve the local domain either through a script argument or by attempting to reverse resolve the local IP.

Script Arguments
broadcast-wpad-discover.getwpad
instructs the script to retrieve the WPAD file instead of parsing it
broadcast-wpad-discover.nodhcp
instructs the script to skip discovery using dhcp
broadcast-wpad-discover.nodns
instructs the script to skip discovery using DNS
broadcast-wpad-discover.domain
the domain in which the WPAD host should be discovered
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script broadcast-wpad-discover

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-wpad-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-wpad-discover  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "29":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-wsdd-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-wsdd-discover.nse

User Summary
Uses a multicast query to discover devices supporting the Web Services Dynamic Discovery (WS-Discovery) protocol. It also attempts to locate any published Windows Communication Framework (WCF) web services (.NET 4.0 or later).

Script Arguments
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
sudo ./nmap --script broadcast-wsdd-discover\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap ---script broadcast-wsdd-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-wsdd-discover -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "30":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-xdmcp-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-xdmcp-discover.nse

User Summary
Discovers servers running the X Display Manager Control Protocol (XDMCP) by sending a XDMCP broadcast request to the LAN. Display managers allowing access are marked using the keyword Willing in the result.

Script Arguments
broadcast-xdmcp-discover.timeout

socket timeout (default: 5s)

Example Usage
nmap --script broadcast-xdmcp-discover
Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-xdmcp-discover '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script broadcast-xdmcp-discover  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "31":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File broadcast-tellstick-discover

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/broadcast-tellstick-discover.nse

User Summary
Discovers Telldus Technologies TellStickNet devices on the LAN. The Telldus TellStick is used to wirelessly control electric devices such as lights, dimmers and electric outlets. For more information: http://www.telldus.com/

Example Usage
nmap --script broadcast-tellstick-discover

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option [Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-tellstick-discover  '+arg+' '+output,shell=True)
            ataoe(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script broadcast-tellstick-discover  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ataoe(host_ip,desc)      
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