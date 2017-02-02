def whois(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for domain name :
    \t[1] whois-domain\n\t[2] whois-ip\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File whois-domain

Script types: hostrule
Categories: discovery, external, safe
Download: http://nmap.org/svn/scripts/whois-domain.nse

User Summary
Attempts to retrieve information about the domain name of the target

Example Usage
nmap --script whois-domain.nse <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script whois-domain '+' '+arg+' '+host_ip+' '+output,shell=True)
            whois(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script whois-domain  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            whois(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File whois-ip

Script types: hostrule
Categories: discovery, external, safe
Download: http://nmap.org/svn/scripts/whois-ip.nse

User Summary
Queries the WHOIS services of Regional Internet Registries (RIR) and attempts to retrieve information about the IP Address
Assignment which contains the Target IP Address.

Script Arguments
whodb
Takes any of the following values, which may be combined:
    whodb=nofile Prevent the use of IANA assignments data and instead query the default services.
    whodb=nofollow Ignore referrals and instead display the first record obtained.
    whodb=nocache Prevent the acceptance of records in the cache when they apply to large ranges of addresses.
    whodb=[service-ids] Redefine the default services to query. Implies nofile.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
    nmap target --script whois-ip
    nmap target --script whois-ip --script-args whodb=nocache
    nmap target --script whois-ip --script-args whois.whodb=nocache


Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script whois-ip '+' '+arg+' '+host_ip+' '+output,shell=True)
            whois(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script whois-ip  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            whois(host_ip,desc)
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