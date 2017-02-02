def llmnr(host_ip,desc) :
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for LLMNR (Link-Local Multicast Name Resolution) protocol:
      [1] llmnr-resolve
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File llmnr-resolve

Script types: prerule
Categories: discovery, safe, broadcast
Download: http://nmap.org/svn/scripts/llmnr-resolve.nse

User Summary
Resolves a hostname by using the LLMNR (Link-Local Multicast Name Resolution) protocol.
The script works by sending a LLMNR Standard Query containing the hostname to the 5355 UDP port on the 224.0.0.252
multicast address. It listens for any LLMNR responses that are sent to the local machine with a 5355 UDP source port.
A hostname to resolve must be provided.
For more information, see:
        http://technet.microsoft.com/en-us/library/bb878128.aspx

Script Arguments
llmnr-resolve.timeout
Max time to wait for a response. (default 3s)
llmnr-resolve.hostname
Hostname to resolve.
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script llmnr-resolve --script-args 'llmnr-resolve.hostname=examplename' -e wlan0

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
            subprocess.call('nmap  --script llmnr-resolve'+' '+interface+' '+arg+' '+host_ip+' '+output,shell=True)
            llmnr(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter=input("Enter your interface name:")
            interface="-e"+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script llmnr-resolve -p '+' '+interface+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            llmnr(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)         
    elif option == "0":
        from ANSE import service_scan
        service_scan(host_ip, desc)
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)                 