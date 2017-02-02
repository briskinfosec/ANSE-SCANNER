def rdp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for RDP service:
    \t[1] rdp-enum-encryption\n\t[2] rdp-vuln-ms12-020\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rdp-enum-encryption

Script types: portrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/rdp-enum-encryption.nse

User Summary
Determines which Security layer and Encryption level is supported by the RDP service. It does so by cycling through
all existing protocols and ciphers. When run in debug mode, the script also returns the protocols and ciphers that fail
and any errors that were reported.
The script was inspired by MWR's RDP Cipher Checker http://labs.mwrinfosecurity.com/tools/2009/01/12/rdp-cipher-checker/

Example Usage
nmap -p 3389 --script rdp-enum-encryption <ip>

Default Option Used in script:
nmap -sV -p 3389 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3389[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3389"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rdp-enum-encryption -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rdp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rdp-enum-encryption -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rdp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rdp-vuln-ms12-020

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/rdp-vuln-ms12-020.nse

User Summary
Checks if a machine is vulnerable to MS12-020 RDP vulnerability.
The Microsoft bulletin MS12-020 patches two vulnerabilities: CVE-2012-0152 which addresses a denial of service vulnerability inside Terminal Server, and CVE-2012-0002 which fixes a vulnerability in Remote Desktop Protocol. Both are part of Remote Desktop Services.
The script works by checking for the CVE-2012-0152 vulnerability. If this vulnerability is not patched, it is assumed that CVE-2012-0002 is not patched either. This script can do its check without crashing the target.

The way this works follows:
    Send one user request. The server replies with a user id (call it A) and a channel for that user.
    Send another user request. The server replies with another user id (call it B) and another channel.
    Send a channel join request with requesting user set to A and requesting channel set to B. If the server replies with a success message, we conclude that the server is vulnerable.
    In case the server is vulnerable, send a channel join request with the requesting user set to B and requesting channel set to B to prevent the chance of a crash.
References:
    http://technet.microsoft.com/en-us/security/bulletin/ms12-020
    http://support.microsoft.com/kb/2621440
    http://zerodayinitiative.com/advisories/ZDI-12-044/
    http://aluigi.org/adv/termdd_1-adv.txt
Original check by by Worawit Wang (sleepya).

Script Arguments
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script=rdp-ms12-020 -p 3389 <target>

Default Option Used in script:
nmap -sV -p 3389 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3389[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3389"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rdp-ms12-020 -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rdp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rdp-ms12-020 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rdp(host_ip,desc)
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