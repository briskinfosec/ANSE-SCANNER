def telnet(host_ip,desc) :
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for telnet servers:
    \t[1] telnet-brute\n\t[2] telnet-encryption\n\t[3] telnet-ntlm-info\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File telnet-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/telnet-brute.nse

User Summary
Performs brute-force password auditing against telnet servers.

Script Arguments
telnet-brute.autosize
Whether to automatically reduce the thread count based on the behavior of the target (default: "true")
telnet-brute.timeout
Connection time-out timespec (default: "5s")
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly,
brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
  nmap -p 23 --script telnet-brute --script-args userdb=myusers.lst,passdb=mypwds.lst,telnet-brute.timeout=8s <target>

Default Option Used in script:
nmap  -sV -p 23 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-23[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="23"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  telnet-brute -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            telnet(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  telnet-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            telnet(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File telnet-encryption

Script types: portrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/telnet-encryption.nse

User Summary
Determines whether the encryption option is supported on a remote telnet server.
Some systems (including FreeBSD and the krb5 telnetd available in many Linux distributions)
implement this option incorrectly, leading to a remote root vulnerability. This script currently
only tests whether encryption is supported, not for that particular vulnerability.

Example Usage
nmap -p 23 <ip> --script telnet-encryption


Default Option Used in script:
nmap  -sV -p 23 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-23[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="23"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  telnet-encryption -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            telnet(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  telnet-encryption -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            telnet(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File telnet-ntlm-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/telnet-ntlm-info.nse

User Summary
This script enumerates information from remote Microsoft Telnet services with NTLM authentication enabled.
Sending a MS-TNAP NTLM authentication request with null credentials will cause the remote service to respond
with a NTLMSSP message disclosing information to include NetBIOS, DNS, and OS build version.

Script Arguments
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 23 --script telnet-ntlm-info <target>

Default Option Used in script:
nmap  -sV -p 23 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-23[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="23"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  telnet-ntlm-info -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            telnet(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  telnet-ntlm-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            telnet(host_ip,desc) 
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