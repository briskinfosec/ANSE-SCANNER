def rmi(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for RMI registry:
    \t[1] rmi-dumpregistry\n\t[2] rmi-vuln-classloader\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rmi-dumpregistry

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/rmi-dumpregistry.nse

User Summary
Connects to a remote RMI registry and attempts to dump all of its objects.
First it tries to determine the names of all objects bound in the registry, and then it tries to determine
information about the objects, such as the the class names of the superclasses and interfaces. This may,
depending on what the registry is used for, give valuable information about the service. E.g, if the app uses
JMX (Java Management eXtensions), you should see an object called "jmxconnector" on it.
It also gives information about where the objects are located, (marked with @<ip>:port in the output).
Some apps give away the classpath, which this scripts catches in so-called "Custom data".

Example Usage
nmap --script "rmi-dumpregistry.nse" -p 1098 <host>

Default Option Used in script:
nmap -sV -p 1098 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1098[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1098"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rmi-dumpregistry -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rmi(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rmi-dumpregistry -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rmi(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rmi-vuln-classloader

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/rmi-vuln-classloader.nse

User Summary
Tests whether Java rmiregistry allows class loading. The default configuration of rmiregistry allows loading classes
from remote URLs, which can lead to remote code execution. The vendor (Oracle/Sun) classifies this as a design feature.
Based on original Metasploit module by mihi.

References:
    https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb

Script Arguments
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script=rmi-vuln-classloader -p 1099 <target>

Default Option Used in script:
nmap -sV -p 1099 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1099[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1099"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rmi-vuln-classloader -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rmi(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rmi-vuln-classloader -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rmi(host_ip,desc)
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