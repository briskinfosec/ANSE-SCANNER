def nat(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for NAT Port Mapping Protocol (NAT-PMP):
    \t[1] nat-pmp-info\n\t[2]  nat-pmp-mapport\n\t\[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File nat-pmp-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/nat-pmp-info.nse

User Summary
Gets the routers WAN IP using the NAT Port Mapping Protocol (NAT-PMP).

Example Usage
nmap -sU -p 5351 --script=nat-pmp-info <target>

Default Option Used in script:
nmap  -sU -p 5351 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-5351[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="5351"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU  --script nat-pmp-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nat(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script nat-pmp-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nat(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File nat-pmp-mapport

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/nat-pmp-mapport.nse

User Summary
Maps a WAN port on the router to a local port on the client using the NAT Port Mapping Protocol (NAT-PMP). It supports the following operations: o map - maps a new external port on the router to an internal port of the requesting IP o unmap - unmaps a previously mapped port for the requesting IP o unmapall - unmaps all previously mapped ports for the requesting IP

Script Arguments
nat-pmp-mapport.op
operation, can be either map, unmap or unmap all o map allows you to map an external port to an internal port of the calling IP o unmap removes the external port mapping for the specified ports and protocol o unmapall removes all mappings for the specified protocol and calling IP
nat-pmp-mapport.protocol
the protocol to map, can be either tcp or udp.
nat-pmp-mapport.privport
the internal port of the calling IP to map requests to. This port will receive all requests coming in to the external port on the router.
nat-pmp-mapport.pubport
the external port to map on the router. The specified port is treated as the requested port. If the port is available it will be allocated to the caller, otherwise the router will simply choose another port, create the mapping and return the resulting port.
nat-pmp-mapport.lifetime
the lifetime of the mapping in seconds (default: 3600)

Example Usage
nmap -sU -p 5351 <ip> --script nat-pmp-mapport --script-args='op=map,pubport=8080,privport=8080,protocol=tcp'
nmap -sU -p 5351 <ip> --script nat-pmp-mapport --script-args='op=unmap,pubport=8080,privport=8080,protocol=tcp'
nmap -sU -p 5351 <ip> --script nat-pmp-mapport --script-args='op=unmapall,protocol=tcp'

Default Option Used in script:
nmap  -sU -p 5351 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-5351[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="5351"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU  --script nat-pmp-mapport -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nat(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script nat-pmp-mapport -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nat(host_ip,desc)
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