def asn(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for  autonomous system (AS)
    \t[1] asn-query\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File asn-query

Script types: hostrule
Categories: discovery, external, safe
Download: http://nmap.org/svn/scripts/asn-query.nse

User Summary
Maps IP addresses to autonomous system (AS) numbers.
The script works by sending DNS TXT queries to a DNS server which in turn queries a third-party service provided by Team Cymru
(https://www.team-cymru.org/Services/ip-to-asn.html) using an in-addr.arpa style zone set up especially for use by Nmap.
The responses to these queries contain both Origin and Peer ASNs and their descriptions,displayed along with the BGP Prefix
and Country Code. The script caches results to reduce the number of queries and should perform
a single query for all scanned targets in a BGP Prefix present in Team Cymru's database.

Script Arguments
dns
The address of a recursive nameserver to use (optional).

Example Usage
nmap --script asn-query [--script-args dns=<DNS server>] <target>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-548 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="548"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script asn-query -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            asn(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script asn-query -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            asn(host_ip,desc)      
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