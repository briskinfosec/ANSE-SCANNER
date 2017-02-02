def eap(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for EAP (Extensible Authentication Protocol:
     [1] eap-info
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File eap-info

Script types: prerule
Categories: broadcast, safe
Download: http://nmap.org/svn/scripts/eap-info.nse

User Summary
Enumerates the authentication methods offered by an EAP (Extensible Authentication Protocol) authenticator
for a given identity or for the anonymous identity if no argument is passed.

Script Arguments
eap-info.identity
Identity to use for the first step of the authentication methods (if omitted "anonymous" will be used).
eap-info.scan
Table of authentication methods to test, e.g. { 4, 13, 25 } for MD5, TLS and PEAP. Default: TLS, TTLS, PEAP, MSCHAP.
eap-info.timeout
Maximum time allowed for the scan (default 10s). Methods not tested because of timeout will be listed as "unknown".
eap-info.interface
Network interface to use for the scan, overrides "-e".

Example Usage
nmap -e interface --script eap-info [--script-args="eap-info.identity=0-user,eap-info.scan={13,50}"] <target>

Default Option Used in script:
nmap -e interface --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445,443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445,443"
            inter=input("Enter your interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script eap-info  -p '+' '+default_port+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            eap(host_ip,desc)   
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            inter = input("Enter your interface name")
            interface = "-e" + ' ' + inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script eap-info  -p '+' '+custom_port+' '+arg+' '+' '+interface+' '+host_ip+' '+output,shell=True)
            eap(host_ip,desc)    
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "0":
        from ANSE import service_scan
        service_scan(host_ip,desc)
    else:
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)                 