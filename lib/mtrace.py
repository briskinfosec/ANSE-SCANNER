def mtrace(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for  IGMP Traceroute:
    \t[1] mtrace\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mtrace

Script types: prerule
Categories: discovery, safe, broadcast
Download: http://nmap.org/svn/scripts/mtrace.nse

User Summary
Queries for the multicast path from a source to a destination host.
This works by sending an IGMP Traceroute Query and listening for IGMP Traceroute responses.
The Traceroute Query is sent to the first hop and contains information about source, destination and multicast group addresses.
First hop defaults to the multicast All routers address. The default multicast group address is 0.0.0.0 and the default destination
is our own host address. A source address must be provided. The responses are parsed to get interesting information about interface addresses,
used protocols and error codes.
This is similar to the mtrace utility provided in Cisco IOS.

Script Arguments
mtrace.fromip
Source address from which to traceroute.
mtrace.group
Multicast group address for the traceroute. Defaults to 0.0.0.0 which represents all group addresses.
mtrace.timeout
Time to wait for responses. Defaults to 7s.
mtrace.firsthop
Host to which the query is sent. If not set, the query will be sent to 224.0.0.2.
mtrace.toip
Destination address to which to traceroute. Defaults to our host address.

Example Usage
nmap --script mtrace --script-args 'mtrace.fromip=172.16.45.4'

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script mtrace'+' '+arg+' '+host_ip+' '+output,shell=True)
            mtrace(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script mtrace -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mtrace(host_ip,desc)
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