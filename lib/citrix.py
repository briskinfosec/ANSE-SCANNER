def citrix(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Citrix PN Web Agent XML Service:
     [1] citrix-brute-xml
     [2] citrix-enum-apps-xml
     [3] citrix-enum-apps
     [4] citrix-enum-servers-xml
     [5] citrix-enum-servers
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File citrix-brute-xml

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/citrix-brute-xml.nse

User Summary
Attempts to guess valid credentials for the Citrix PN Web Agent XML Service. The XML service authenticates
against the localWindows server or the Active Directory.
This script makes no attempt of preventing account lockout. If the password list contains more passwords than the
lockout-threshold accounts will be locked.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
Example Usage
nmap --script=citrix-brute-xml --script-args=userdb=<userdb>,passdb=<passdb>,ntdomain=<domain> -p 80,443,8080 <host>

Default Option Used in script:
nmap --script [script name] -p 80,443,8080 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option port-80,443,8080[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,443,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script citrix-brute-xml-p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script citrix-brute-xml -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File citrix-enum-apps-xml

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/citrix-enum-apps-xml.nse

User Summary
Extracts a list of applications, ACLs, and settings from the Citrix XML service.
The script returns more output with higher verbosity.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=citrix-enum-apps-xml -p 80,443,8080 <host>

Default Option Used in script:
nmap --script [script name] -p 80,443,8080 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-80,443,8080[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,443,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script citrix-enum-apps-xml -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script citrix-enum-apps-xml -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File citrix-enum-apps

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/citrix-enum-apps.nse

User Summary
Extracts a list of published applications from the ICA Browser service.

Example Usage
sudo ./nmap -sU --script=citrix-enum-apps -p 1604 <host

Default Option Used in script:
nmap -sU --script [script name] -p 1604 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default Option port-1604 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1604"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script citrix-enum-apps '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script citrix-enum-apps -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File citrix-enum-servers-xml

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/citrix-enum-servers-xml.nse
User Summary

Extracts the name of the server farm and member servers from Citrix XML service.
Script Arguments

slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=citrix-enum-servers-xml -p 80,443,8080 <host>

Default Option Used in script:
nmap --script [script name] -p 80,443,8080 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option port-80,443,8080[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port ="80,443,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script citrix-enum-servers-xml '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script citrix-enum-servers-xml -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)        
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File citrix-enum-servers

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/citrix-enum-servers.nse
User Summary

Extracts a list of Citrix servers from the ICA Browser service.

Example Usage
sudo ./nmap -sU --script=citrix-enum-servers -p 1604

Default Option Used in script:
nmap --script [script name] -p 80,443,8080 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-80,443,8080 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="80,443,8080"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script citrix-enum-servers '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script citrix-enum-servers -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            citrix(host_ip,desc)      
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