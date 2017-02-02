 #!/usr/bin/env python3
def afp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
  +Choose your NSE script for Apple Filing Protocol
  [1] afp-brute
  [2] afp-ls
  [3] afp-path-vuln
  [4] afp-serverinfo
  [5] afp-serverinfo
  [6] afp-showmount
  [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File afp-brute
Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/afp-brute.nse

User Summary
Performs password guessing against Apple Filing Protocol (AFP).

Script Arguments
afp.password, afp.username
See the documentation for the afp library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap -p 548 --script afp-brute <host>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-548 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="548"
            arg=input("Enter argument if you need or press just enter:")
            output="-oN"+' '+"output/"+host_ip+"afp-brute-1.txt"
            subprocess.call('nmap --script afp-brute -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            afp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            output="-oN"+' '+"output/"+host_ip+"afp-brute.txt"
            arg=input("Enter argument if you need or press just enter:")
            subprocess.call('nmap --script afp-brute  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            afp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File afp-ls
Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/afp-ls.nse

User Summary
Attempts to get useful information about files from AFP volumes. The output is intended to resemble the output of ls.

Script Arguments
afp.password, afp.username
See the documentation for the afp library.
ls.checksum, ls.empty, ls.errors, ls.human, ls.maxdepth, ls.maxfiles
See the documentation for the ls library.

Example Usage
nmap -sS -sV -p 548 --script=afp-ls target\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-548 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="548"
            arg=input("Enter argument if you need or press just enter:")
            output="-oN"+' '+"../output/"+host_ip+"-afp-ls.txt"
            subprocess.call('nmap -sS -sV --script afp-ls -p '+default_port+' '+arg+' '+host_ip,shell=True)
            afp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            output="-oN"+' '+"output/"+host_ip+"-afp-ls.txt"
            subprocess.call('nmap -sS -sV --script afp-ls  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            afp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File afp-path-vuln

Script types: portrule
Categories: exploit, intrusive, vuln
Download: http://nmap.org/svn/scripts/afp-path-vuln.nse

User Summary
Detects the Mac OS X AFP directory traversal vulnerability, CVE-2010-0533.
This script attempts to iterate over all AFP shares on the remote host. For each share it attempts to access
the parent directory by exploiting the directory traversal vulnerability as described in CVE-2010-0533.
The script reports whether the system is vulnerable or not. In addition it lists the contents of the parent
and child directories to a max depth of 2. When running in verbose mode, all items in the listed directories are shown.
In non verbose mode, output is limited to the first 5 items.
If the server is not vulnerable, the script will not return any information.

For additional information:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0533
    http://www.cqure.net/wp/2010/03/detecting-apple-mac-os-x-afp-vulnerability-cve-2010-0533-with-nmap
    http://support.apple.com/kb/HT1222

Script Arguments
afp.password, afp.username
See the documentation for the afp library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script=afp-path-vuln <target>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-548 [Y/N/Nil]:")
        if port_select == "Y" or port_select == "y":
            default_port="548"
            arg=input("Enter argument if you need or press just enter:")
            output="-oN"+' '+"output/"+host_ip+"-afp-path-vuln.txt"
            subprocess.call('nmap -sV --script afp-path-vuln -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            afp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            output="-oN"+' '+host_ip+"afp-path-vuln.txt"
            subprocess.call('nmap -sV --script afp-path-vuln  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            afp(host_ip,desc)
        elif port_select == "Nil" or port_select == "nil":
            arg=input("Enter argument if you need or press just enter:")
            output="-oN"+' '+host_ip+"afp-path-vuln.txt"
            subprocess.call('nmap -sV --script afp-path-vuln '+arg+' '+host_ip+' '+output,shell=True)
            afp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File afp-serverinfo

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/afp-serverinfo.nse

User Summary
Shows AFP server information. This information includes the server's hostname, IPv4 and IPv6 addresses,
and hardware type (for example Macmini or MacBookPro).

Script Arguments
afp.password, afp.username
See the documentation for the afp library.

Example Usage
nmap -sV -sC <target>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-548 [Y/N/Nil]:")
        if port_select == "Y" or port_select == "y":
            default_port="548"
            arg=input("Enter argument if you need or press just enter:")
            output="-oN"+' '+host_ip+"afp-serverinfo.txt"
            subprocess.call('nmap -sS -sV --script afp-serverinfo -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            afp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            output="-oN"+' '+host_ip+"afp-serverinfo.txt"
            subprocess.call('nmap -sS -sV --script afp-serverinfo  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            afp(host_ip,desc)
        elif port_select == "Nil" or port_select == "nil":
            arg=input("Enter argument if you need or press just enter:")
            output="-oN"+' '+"output/"+host_ip+"afp-serverinfo.txt"
            subprocess.call('nmap -sS -sV --script afp-serverinfo '+arg+' '+host_ip+' '+output,shell=True)
            afp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File afp-showmount

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/afp-showmount.nse

User Summary
Shows AFP shares and ACLs.

Script Arguments
afp.password, afp.username
See the documentation for the afp library.

Example Usage
nmap -sV --script=afp-showmount <target>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-548 [Y/N/Nil]:")
        if port_select == "Y" or port_select == "y":
            default_port="548"
            arg=input("Enter argument if you need or press just enter:")
            subprocess.call('nmap  -sV --script afp-showmount -p '+default_port+' '+arg+' '+host_ip,shell=True)
            afp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            subprocess.call('nmap  -sV --script afp-serverinfo  -p '+custom_port+' '+arg+' '+host_ip,shell=True)
            afp(host_ip,desc)
        elif port_select == "Nil" or port_select == "nil":
            arg=input("Enter argument if you need or press just enter:")
            subprocess.call('nmap  -sV --script afp-serverinfo '+arg+' '+host_ip,shell=True)
            afp(host_ip,desc)
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
