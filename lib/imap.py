def imap(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for IMAP servers:
      [1] imap-brute
      [2] imap-capabilities
      [3] imap-ntlm-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File imap-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/imap-brute.nse

User Summary
Performs brute force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.
Script Arguments

imap-brute.auth
authentication mechanism to use LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 143,993 --script imap-brute <host>

Default Option Used in script:
nmap -p 143,993 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-143,993[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="143,993"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script imap-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            imap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script imap-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            imap(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File imap-capabilities

Script types: portrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/imap-capabilities.nse

User Summary
Retrieves IMAP email server capabilities.
IMAP4rev1 capabilities are defined in RFC 3501. The CAPABILITY command allows a client to ask a server what commands it supports and possibly any site-specific policy.

Script Arguments
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -sV -sC <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  imap-capabilities'+' '+arg+' '+host_ip+' '+output,shell=True)
            imap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  imap-capabilities -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            imap(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File imap-ntlm-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/imap-ntlm-info.nse

User Summary
This script enumerates information from remote IMAP services with NTLM authentication enabled.
Sending an IMAP NTLM authentication request with null credentials will cause the remote service to respond with a NTLMSSP message disclosing information to include NetBIOS, DNS, and OS build version.

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
nmap -p 143,993 --script imap-ntlm-info <target>ost>

Default Option Used in script:
nmap -p 143,993 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-143,993[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="143,993"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script imap-ntlm-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            imap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script imap-ntlm-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            imap(host_ip,desc)
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