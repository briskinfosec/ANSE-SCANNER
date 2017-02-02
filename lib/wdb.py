def wdb(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for VxWorks Wind DeBug agents:
    \t[1] wdb-version\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File wdb-version

Script types: portrule
Categories: default, version, discovery, vuln
Download: http://nmap.org/svn/scripts/wdb-version.nse

User Summary
Detects vulnerabilities and gathers information (such as version numbers and hardware support) from VxWorks Wind DeBug agents.
Wind DeBug is a SunRPC-type service that is enabled by default on many devices that use the popular VxWorks real-time embedded operating system. H.D. Moore of Metasploit has identified several security vulnerabilities and design flaws with the service, including weakly-hashed passwords and raw memory dumping.
See also: http://www.kb.cert.org/vuls/id/362332

Script Arguments
mount.version, nfs.version, rpc.protocol
See the documentation for the rpc library.

Example Usage
nmap -sU -p 17185 --script wdb-version <target>

Default Option Used in script:
nmap  -sV  -sU  -p 17185 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-17185[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="17185"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script   voldemort-info -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            wdb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  -sU  voldemort-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            wdb(host_ip,desc)
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