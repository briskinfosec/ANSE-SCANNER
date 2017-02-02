def stun(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for STUN protocol:
    \t[1] stun-info\n\t[2] stun-version\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File stun-info

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/stun-info.nse

User Summary
Retrieves the external IP address of a NAT:ed host using the STUN protocol.

Script Arguments
stun.mode
See the documentation for the stun library.

Example Usage
nmap -sV -PN -sU -p 3478 --script stun-info <ip>

Default Option Used in script:
nmap  -sV -PN -sU 3478 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3478[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3478"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -PN -sU --script  stun-info -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            stun(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  stun-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            stun(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File stun-version

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/stun-version.nse

User Summary
Sends a binding request to the server and attempts to extract version information from the response, if the server attribute is present.

Script Arguments
stun.mode
See the documentation for the stun library.

Example Usage
nmap -sU -sV -p 3478 <target>

Default Option Used in script:
nmap  -sV -PN -sU 3478 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3478[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3478"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -PN -sU --script  stun-version -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            stun(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  stun-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            stun(host_ip,desc)
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