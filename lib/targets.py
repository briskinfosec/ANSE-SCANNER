def targets(host_ip,desc) :
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for routing AS number (ASN):
    \t[1] targets-asn\n\t[2] targets-ipv6-map4to6\n\t[3] targets-ipv6-multicast-echo\n\t[4] targets-ipv6-multicast-invalid-dst
    \t[5] targets-ipv6-multicast-mld\n\t[6] targets-ipv6-multicast-slaac\n\t[7] targets-ipv6-wordlist\n\t[8] targets-sniffer
    \t[9] targets-traceroute
       [10] targets-xml\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-asn

Script types: prerule
Categories: discovery, external, safe
Download: http://nmap.org/svn/scripts/targets-asn.nse

User Summary
Produces a list of IP prefixes for a given routing AS number (ASN).
This script uses a whois server database operated by the Shadowserver Foundation.


Script Arguments
targets-asn.whois_port
The whois port to use. Default: 43.
targets-asn.whois_server
The whois server to use. Default: asn.shadowserver.org.
targets-asn.asn
The ASN to search.
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script targets-asn --script-args targets-asn.asn=32

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script targets-asn '+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script targets-asn  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-ipv6-map4to6

Script types: prerule
Categories: discovery
Download: http://nmap.org/svn/scripts/targets-ipv6-map4to6.nse

User Summary
This script runs in the pre-scanning phase to map IPv4 addresses onto IPv6 networks and add them to the scan queue.
The technique is more general than what is technically termed "IPv4-mapped IPv6 addresses." The lower 4 bytes of the
IPv6 network address are replaced with the 4 bytes of IPv4 address. When the IPv6 network is ::ffff:0:0/96, then the
script generates IPv4-mapped IPv6 addresses. When the network is ::/96, then it generates IPv4-compatible IPv6 addresses.

Script Arguments
targets-ipv6-map4to6.IPv4Hosts
This must have at least one IPv4 Host for the script be able to work (Ex. 192.168.1.1 or { 192.168.1.1, 192.168.2.2 } )
or Subnet Addresses ( 192.168.1.0/24 or { 192.168.1.0/24, 192.168.2.0/24 } )
targets-ipv6-subnet
Table/single IPv6 address with prefix (Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 })
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap -6 --script targets-ipv6-map4to6 --script-args newtargets,targets-ipv6-map4to6.IPv4Hosts={192.168.1.0/24},targets-ipv6-subnet={2001:db8:c0ca::/64}

Default Option Used in script:
nmap -6 -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -6  -sV --script targets-ipv6-map4to6 '+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6  --script targets-ipv6-map4to6  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-ipv6-multicast-echo

Script types: prerule
Categories: discovery, broadcast
Download: http://nmap.org/svn/scripts/targets-ipv6-multicast-echo.nse

User Summary
Sends an ICMPv6 echo request packet to the all-nodes link-local multicast address (ff02::1) to discover responsive hosts on a LAN without needing to individually ping each IPv6 address.

Script Arguments
newtargets
If true, add discovered targets to the scan queue.
targets-ipv6-multicast-echo.interface
The interface to use for host discovery.
max-newtargets
See the documentation for the target library.

Example Usage
./nmap -6 --script=targets-ipv6-multicast-echo.nse --script-args 'newtargets,interface=eth0' -sL
Default Option Used in script:
nmap -6 -sV -sL  --script [script name]  [arg] [interface_name]  [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -6  -sL -sV --script targets-ipv6-multicast-echo '+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 -sL --script targets-ipv6-multicast-echo  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-ipv6-multicast-invalid-dst

Script types: prerule
Categories: discovery, broadcast
Download: http://nmap.org/svn/scripts/targets-ipv6-multicast-invalid-dst.nse

User Summary
Sends an ICMPv6 packet with an invalid extension header to the all-nodes link-local multicast address
(ff02::1) to discover (some) available hosts on the LAN. This works because some hosts will respond to this
probe with an ICMPv6 Parameter Problem packet.

Script Arguments
newtargets
If true, add discovered targets to the scan queue.
targets-ipv6-multicast-invalid-dst.interface
The interface to use for host discovery.
max-newtargets
See the documentation for the target library.

Example Usage
./nmap -6 --script=targets-ipv6-multicast-invalid-dst.nse --script-args 'newtargets,interface=eth0' -sP

Default Option Used in script:
nmap -6 -sV -sP -e interface --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 -sV -sP --script targets-ipv6-multicast-invalid-dst  -p '+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)     
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter = input("Enter your interface name")
            interface = "-e" + ' ' + inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 -sP  --script targets-ipv6-multicast-invalid-dst  -p '+' '+custom_port+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-ipv6-multicast-mld

Script types: prerule
Categories: discovery, broadcast
Download: http://nmap.org/svn/scripts/targets-ipv6-multicast-mld.nse

User Summary
Attempts to discover available IPv6 hosts on the LAN by sending an MLD (multicast listener discovery) query
to the link-local multicast address (ff02::1) and listening for any responses. The query's maximum response delay
set to 1 to provoke hosts to respond immediately rather than waiting for other responses from their multicast group.

Script Arguments
targets-ipv6-multicast-mld.interface
Interface to send on (default: the interface specified with -e or every available Ethernet interface with an IPv6 address.)
targets-ipv6-multicast-mld.timeout
timeout to wait for responses (default: 10s)
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap -6 --script=targets-ipv6-multicast-mld.nse --script-args 'newtargets,interface=eth0'

Default Option Used in script:
nmap -6 -sV -e interface --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 -sV  --script targets-ipv6-multicast-mld  -p '+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter = input("Enter your interface name")
            interface = "-e" + ' ' + inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6  --script targets-ipv6-multicast-mld  -p '+' '+custom_port+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)       
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-ipv6-multicast-slaac

Script types: prerule
Categories: discovery, broadcast
Download: http://nmap.org/svn/scripts/targets-ipv6-multicast-slaac.nse

User Summary
Performs IPv6 host discovery by triggering stateless address auto-configuration (SLAAC).
This script works by sending an ICMPv6 Router Advertisement with a random address prefix,
which causes hosts to begin SLAAC and send a solicitation for their newly configured address,
as part of duplicate address detection. The script then guesses the remote addresses by combining
the link-local prefix of the interface with the interface identifier in each of the received solicitations.
This should be followed up with ordinary ND host discovery to verify that the guessed addresses are correct.
The router advertisement has a router lifetime of zero and a short prefix lifetime (a few seconds)


Script Arguments
targets-ipv6-multicast-slaac.interface
The interface to use for host discovery.
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap -6 --script targets-ipv6-multicast-slaac --script-args 'newtargets,interface=eth0' -sP

Default Option Used in script:
nmap -6 -sV -sP -e interface --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 -sV -sP  --script targets-ipv6-multicast-slaac  -p '+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter = input("Enter your interface name")
            interface = "-e" + ' ' + inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6  --script targets-ipv6-multicast-slaac  -p '+' '+custom_port+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)       
        else:
            os.system('clear')
            print(desc)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-ipv6-wordlist

Script types: prerule
Categories: discovery
Download: http://nmap.org/svn/scripts/targets-ipv6-wordlist.nse

User Summary
Adds IPv6 addresses to the scan queue using a wordlist of hexadecimal "words" that form addresses in a given subnet.

Script Arguments
targets-ipv6-wordlist.nsegments
Number User can indicate exactly how big the word must be on Segments of 16 bits.
targets-ipv6-wordlist.fillright
With this argument the script will fill remaining zeros to the right instead of left (2001:db8:c0a:dead:: instead of 2001:db8:c0ca::dead)
targets-ipv6-subnet
table/single IPv6 address with prefix (Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )
targets-ipv6-wordlist.wordlist
File containing hexadecimal words for building addresses, one per line. Default: nselib/data/targets-ipv6-wordlist
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap -6 -p 80 --script targets-ipv6-wordlist --script-args newtargets,targets-ipv6-subnet={2001:db8:c0ca::/64}

Default Option Used in script:
nmap -6 -sV -p 80 -e interface --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80"
            inter=input("Enter your interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 -sV  --script targets-ipv6-wordlist  -p '+' '+default_port+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter = input("Enter your interface name")
            interface = "-e" + ' ' + inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6  --script targets-ipv6-wordlist  -p '+' '+custom_port+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)       
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-sniffer

Script types: prerule
Categories: broadcast, discovery, safe
Download: http://nmap.org/svn/scripts/targets-sniffer.nse

User Summary
Sniffs the local network for a configurable amount of time (10 seconds by default) and prints discovered addresses.
If the newtargets script argument is set, discovered addresses are added to the scan queue.
Requires root privileges. Either the targets-sniffer.iface script argument or -e Nmap option to define which interface to use.

Script Arguments
targets-sniffer.iface
The interface to use for sniffing.
targets-sniffer.timeout
The amount of time to listen for packets. Default 10s.
newtargets
If true, add discovered targets to the scan queue.
max-newtargets
See the documentation for the target library.

Example Usage
nmap -sL --script=targets-sniffer --script-args=newtargets,targets-sniffer.timeout=5s,targets-sniffer.iface=eth0

Default Option Used in script:
nmap -6 -sV  -sL -e interface --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-80[Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6 -sV -sL  --script targets-sniffer  -p '+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter = input("Enter your interface name")
            interface = "-e" + ' ' + inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -6  -sV -sL --script targets-sniffer  -p '+' '+custom_port+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc)       
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-traceroute

Script types: hostrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/targets-traceroute.nse

User Summary
Inserts traceroute hops into the Nmap scanning queue. It only functions if Nmap's --traceroute option is
used and the newtargets script argument is given.

Script Arguments
newtargets
If specified, adds traceroute hops onto Nmap scanning queue.
max-newtargets
See the documentation for the target library.

Example Usage
nmap --script targets-traceroute --script-args newtargets --traceroute target

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script targets-traceroute '+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script targets-traceroute  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "10":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File targets-xml

Script types: prerule
Categories: safe
Download: http://nmap.org/svn/scripts/targets-xml.nse

User Summary
Loads addresses from an Nmap XML output file for scanning.
Address type (IPv4 or IPv6) is determined according to whether -6 is specified to nmap.

Script Arguments
targets-xml.iX
Filename of an Nmap XML file to import
targets-xml.state
Only hosts with this status will have their addresses input. Default: "up"
max-newtargets, newtargets
See the documentation for the target library.
slaxml.debug
See the documentation for the slaxml library.

Example Usage
nmap --script targets-xml --script-args newtargets,iX=oldscan.xml

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script targets-xml '+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script targets-xml  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            targets(host_ip,desc) 
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