def ip(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for IP Address:
     [1] ip-forwarding
     [2] ip-geolocation-geoplugin
     [3] ip-geolocation-ipinfodb
     [4] ipidseq
     [5] ip-https-discover
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ip-forwarding

Script types: hostrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/ip-forwarding.nse

User Summary
Detects whether the remote device has ip forwarding or "Internet connection sharing" enabled, by sending an ICMP
echo request to a given target using the scanned host as default gateway.
The given target can be a routed or a LAN host and needs to be able to respond to ICMP requests (ping) in order
for the test to be successful. In addition, if the given target is a routed host, the scanned host needs to have
the proper routing to reach it.
In order to use the scanned host as default gateway Nmap needs to discover the MAC address. This requires Nmap
to be run in privileged mode and the host to be on the LAN.

Script Arguments
ip-forwarding.target
a LAN or routed target responding to ICMP echo requests (ping).

Example Usage
sudo nmap -sn <target> --script ip-forwarding --script-args='target=www.example.com'

Default Option Used in script:
nmap -sn --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn --script ip-forwarding'+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn --script ip-forwarding -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ip-geolocation-geoplugin

Script types: hostrule
Categories: discovery, external, safe
Download: http://nmap.org/svn/scripts/ip-geolocation-geoplugin.nse

User Summary
Tries to identify the physical location of an IP address using the Geoplugin geolocation web service (http://www.geoplugin.com/). There is no limit on lookups using this service.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script ip-geolocation-geoplugin <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ip-geolocation-geoplugin'+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ip-geolocation-geoplugin -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ip-geolocation-ipinfodb

Script types: hostrule
Categories: discovery, external, safe
Download: http://nmap.org/svn/scripts/ip-geolocation-ipinfodb.nse

User Summary
Tries to identify the physical location of an IP address using the IPInfoDB geolocation web service (http://ipinfodb.com/ip_location_api.php).
There is no limit on requests to this service. However, the API key needs to be obtained through free registration for this service: http://ipinfodb.com/login.php

Script Arguments
ip-geolocation-ipinfodb.apikey
A sting specifying the api-key which the user wants to use to access this service
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script ip-geolocation-ipinfodb <target> --script-args ip-geolocation-ipinfodb.apikey=<API_key>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ip-geolocation-ipinfodb'+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ip-geolocation-ipinfodb -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ipidseq

Script types: hostrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/ipidseq.nse

User Summary
Classifies a host's IP ID sequence (test for susceptibility to idle scan).
Sends six probes to obtain IP IDs from the target and classifies them similarly to Nmap's method. This is useful for finding suitable zombies for Nmap's idle scan (-sI) as Nmap itself doesn't provide a way to scan for these hosts.

Script Arguments
probeport
Set destination port to probe

Example Usage
nmap --script ipidseq [--script-args probeport=port] target

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ipidseq'+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ipidseq -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ip-https-discover

Script types: portrule
Categories: discovery, safe, default
Download: http://nmap.org/svn/scripts/ip-https-discover.nse

User Summary
Checks if the IP over HTTPS (IP-HTTPS) Tunneling Protocol [1] is supported.
IP-HTTPS sends Teredo related IPv6 packets over an IPv4-based HTTPS session. This indicates that Microsoft
DirectAccess [2], which allows remote clients to access intranet resources on a domain basis, is supported. Windows
clients need Windows 7 Enterprise/Ultime or Windows 8.1 Enterprise/Ultimate. Servers need Windows Server 2008 (R2) or
Windows Server 2012 (R2). Older versions of Windows and Windows Server are not supported.
[1] http://msdn.microsoft.com/en-us/library/dd358571.aspx [2] http://technet.microsoft.com/en-us/network/dd420463.aspx

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script ip-https-discover

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ip-https-discover'+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ip-https-discover -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ip(host_ip,desc)
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
            