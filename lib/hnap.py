def hnap(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for hardwares details and configuration information utilizing HNAP:
      [1] hnap-info
      [2] hostmap-bfk
      [3] hostmap-ip2hostsn
      [4] hostmap-robtex
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hnap-info

Script types: portrule
Categories: safe, discovery, default
Download: http://nmap.org/svn/scripts/hnap-info.nse

User Summary
Retrieve hardwares details and configuration information utilizing HNAP, the "Home Network Administration Protocol".

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script hnap-info -p80,8080 <target>

Default Option Used in script:
nmap -sV  -p 80,8080 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,8080[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script hnap-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hnap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script hnap-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hnap(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hostmap-bfk

Script types: hostrule
Categories: external, discovery
Download: http://nmap.org/svn/scripts/hostmap-bfk.nse

User Summary
Discovers hostnames that resolve to the target's IP address by querying the online database at
http://www.bfk.de/bfk_dnslogger.html.

Script Arguments
hostmap-bfk.prefix
If set, saves the output for each host in a file called "<prefix><target>". The file contains one entry per line.
newtargets
If set, add the new hostnames to the scanning queue. This the names presumably resolve to the same IP address as
the original target, this is only useful for services such as HTTP that can change their behavior based on hostname.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
max-newtargets
See the documentation for the target library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script hostmap-bfk --script-args hostmap-bfk.prefix=hostmap- <targets>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script hostmap-bfk'+' '+arg+' '+host_ip+' '+output,shell=True)
            hnap(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script hostmap-bfk -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hnap(host_ip,desc)  
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hostmap-ip2hosts

Script types: hostrule
Categories: external, discovery
Download: http://nmap.org/svn/scripts/hostmap-ip2hosts.nse

User Summary
Finds hostnames that resolve to the target's IP address by querying the online database:


Script Arguments
newtargets
If set, add the new hostnames to the scanning queue. This the names presumably resolve to the same IP address
as the original target, this is only useful for services such as HTTP that can change their behavior based on hostname.
hostmap.prefix
If set, saves the output for each host in a file called "<prefix><target>". The file contains one entry per line.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
max-newtargets
See the documentation for the target library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script hostmap-ip2hosts --script-args 'hostmap-ip2hosts.prefix=hostmap-' <targets>
nmap -sn --script hostmap-ip2hosts <target>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn --script hostmap-ip2hosts'+' '+arg+' '+host_ip+' '+output,shell=True)
            hnap(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn --script hostmap-ip2hosts -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hnap(host_ip,desc)  
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hostmap-robtex

Script types: hostrule
Categories: discovery, safe, external
Download: http://nmap.org/svn/scripts/hostmap-robtex.nse

User Summary
Discovers hostnames that resolve to the target's IP address by querying the online Robtex service at http://ip.robtex.com/.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script hostmap-robtex -sn -Pn scanme.nmap.org

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn -Pn -script hostmap-robtex'+' '+arg+' '+host_ip+' '+output,shell=True)
            hnap(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn -Pn  --script hostmap-robtex -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hnap(host_ip,desc)  
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
     