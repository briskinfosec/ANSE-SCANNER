def netbus(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for NetBus:
    \t[1] netbus-auth-bypass\n\t[2] netbus-brute\n\t[3] netbus-info\n\t[4] netbus-version\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File netbus-auth-bypass

Script types: portrule
Categories: auth, safe, vuln
Download: http://nmap.org/svn/scripts/netbus-auth-bypass.nse

User Summary
Checks if a NetBus server is vulnerable to an authentication bypass vulnerability which allows full access without knowing the password.
For example a server running on TCP port 12345 on localhost with this vulnerability is accessible to anyone. An attacker could simply form a connection to the server ( ncat -C 127.0.0.1 12345 ) and login to the service by typing Password;1; into the console.

Example Usage
nmap -p 12345 --script netbus-auth-bypass <target>

Default Option Used in script:
nmap -sV -p 12345 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-12345[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="12345"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script netbus-auth-bypass -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            netbus(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script netbus-auth-bypass -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            netbus(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File netbus-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/netbus-brute.nse
User Summary
Performs brute force password auditing against the Netbus backdoor ("remote administration") service.

Script Arguments
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap -p 12345 --script netbus-brute <target>

Default Option Used in script:
nmap -sV -p 12345 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-12345[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="12345"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script netbus-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            netbus(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script netbus-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            netbus(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File netbus-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/netbus-info.nse

User Summary
Opens a connection to a NetBus server and extracts information about the host and the NetBus service itself.
The extracted host information includes a list of running applications, and the hosts sound volume settings.
The extracted service information includes its access control list (acl), server information, and setup.
The acl is a list of IP addresses permitted to access the service. Server information contains details about
the server installation path, restart persistence, user account that the server is running on, and the amount
of connected NetBus clients. The setup information contains configuration details, such as the services TCP port number,
traffic logging setting, password, an email address for receiving login notifications, an email address used for sending
the notifications, and an smtp-server used for notification delivery.

Script Arguments
netbus-info.password
The password used for authentication

Example Usage
nmap -p 12345 --script netbus-info <target> --script-args netbus-info.password=<password>

Default Option Used in script:
nmap  -sV  -p 12345 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-12345[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="12345"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script netbus-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            netbus(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script netbus-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            netbus(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File netbus-version

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/netbus-version.nse

User Summary
Extends version detection to detect NetBuster, a honeypot service that mimes NetBus.

Example Usage
nmap -sV -p 12345 --script netbus-version <target>

Default Option Used in script:
nmap -sV -p 12345 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-12345[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="12345"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script netbus-version -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            netbus(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script netbus-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            netbus(host_ip,desc)
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
