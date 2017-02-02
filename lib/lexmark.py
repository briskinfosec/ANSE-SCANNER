def lexmark(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Lexmark S300-S400 printer:
     [1] Lexmark S300-S400 printer
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File lexmark-config

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/lexmark-config.nse

User Summary
Retrieves configuration information from a Lexmark S300-S400 printer.
The Lexmark S302 responds to the NTPRequest version probe with its configuration. The response decodes as mDNS, so the request was modified to resemble an mDNS request as close as possible. However, the port (9100/udp) is listed as something completely different (HBN3) in documentation from Lexmark. See http://www.lexmark.com/vgn/images/portal/Security%20Features%20of%20Lexmark%20MFPs%20v1_1.pdf.

Example Usage
nmap -sU -p 9100 --script=lexmark-config <target>

Default Option Used in script:
nmap  -sU  -p  9100  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-9100[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="9100"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU  --script ldap-search -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            lexmark(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sU --script ldap-search -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            lexmark(host_ip,desc)
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
        