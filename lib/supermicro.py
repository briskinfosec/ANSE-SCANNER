def supermicro(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Supermicro Onboard IPMI controllers:
    \t[1] supermicro-ipmi-conf\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File supermicro-ipmi-conf

Script types: portrule
Categories: exploit, vuln
Download: http://nmap.org/svn/scripts/supermicro-ipmi-conf.nse

User Summary
Attempts to download an unprotected configuration file containing plain-text user credentials in vulnerable Supermicro Onboard
IPMI controllers.
The script connects to port 49152 and issues a request for "/PSBlock" to download the file. This configuration file contains
users with their passwords in plain text.

Script Arguments
supermicro-ipmi-conf.out
Output file to store configuration file. Default: <ip>_bmc.conf
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -p49152 --script supermicro-ipmi-conf <target>

Default Option Used in script:
nmap  -sV -p 49152 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-49152[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="49152"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  supermicro-ipmi-conf -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            supermicro(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  supermicro-ipmi-conf -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            supermicro(host_ip,desc)
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