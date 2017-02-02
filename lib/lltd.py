def lltd(host_ip,desc) :
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Microsoft LLTD protocol:
      [1] lltd-discovery
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File lltd-discovery

Script types: prerule
Categories: broadcast, discovery, safe
Download: http://nmap.org/svn/scripts/lltd-discovery.nse

User Summary
Uses the Microsoft LLTD protocol to discover hosts on a local network.
For more information on the LLTD protocol please refer to http://www.microsoft.com/whdc/connect/Rally/LLTD-spec.mspx

Script Arguments
lltd-discovery.interface
string specifying which interface to do lltd discovery on. If not specified, all ethernet interfaces are tried.
lltd-discover.timeout
timespec specifying how long to listen for replies (default 30s)
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap -e <interface> --script lltd-discovery

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
            subprocess.call('nmap  --script lltd-discovery'+' '+interface+' '+arg+' '+host_ip+' '+output,shell=True)
            lltd(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter=input("Enter your interface name:")
            interface="-e"+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script lltd-discovery -p '+' '+interface+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            lltd(host_ip,desc) 
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