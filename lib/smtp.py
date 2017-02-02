def smtp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for SMTP servers:
    \t[1] smtp-brute\n\t[2] smtp-commands\n\t[3] smtp-enum-users\n\t[4] smtp-ntlm-info\n\t[5] smtp-open-relay\n\t[6] smtp-strangepor
    \t[7] smtp-vuln-cve2010-4344\n\t[8] smtp-vuln-cve2011-1720\n\t[9] smtp-vuln-cve2011-1764\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smtp-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/smtp-brute.nse

User Summary
Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.

Script Arguments
smtp-brute.auth
authentication mechanism to use LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM
creds.[service], creds.global
See the documentation for the creds library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
smtp.domain
See the documentation for the smtp library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap -p 25 --script smtp-brute <host>

Default Option Used in script:
nmap  -sV -p 25 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-25[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="25"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-brute -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smtp-commands

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/smtp-commands.nse

User Summary
Attempts to use EHLO and HELP to gather the Extended commands supported by an SMTP server.

Script Arguments
smtp.domain
or smtp-commands.domain Define the domain to be used in the SMTP commands.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smtp-commands.nse [--script-args smtp-commands.domain=<domain>] -pT:25,465,587 <host>

Default Option Used in script:
nmap  -sV -p 25,465,587 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-25,465,587[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="25,465,587"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-commands -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-commands -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smtp-enum-users

Script types: portrule
Categories: auth, external, intrusive
Download: http://nmap.org/svn/scripts/smtp-enum-users.nse

User Summary
Attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands.
The goal of this script is to discover all the user accounts in the remote system.
The script will output the list of user names that were found. The script will stop querying the SMTP server
if authentication is enforced. If an error occurs while testing the target host, the error will be printed
with the list of any combinations that were found prior to the error.
The user can specify which methods to use and in which order. The script will ignore repeated methods.
If not specified the script will use the RCPT first, then VRFY and EXPN. An example of how to specify the methods to use and the order is the following:
smtp-enum-users.methods={EXPN,RCPT,VRFY}

Script Arguments
smtp.domain
or smtp-enum-users.domain Define the domain to be used in the SMTP commands
smtp-enum-users.methods
Define the methods and order to be used by the script (EXPN, VRFY, RCPT)
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smtp-enum-users.nse [--script-args smtp-enum-users.methods={EXPN,...},...] -p 25,465,587 <host>

Default Option Used in script:
nmap  -sV -p 25,465,587 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-25,465,587[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="25,465,587"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-enum-users -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-enum-users -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smtp-ntlm-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/smtp-ntlm-info.nse

User Summary
This script enumerates information from remote SMTP services with NTLM authentication enabled.
Sending a SMTP NTLM authentication request with null credentials will cause the remote service
to respond with a NTLMSSP message disclosing information to include NetBIOS, DNS, and OS build version.

Script Arguments
smtp.domain
See the documentation for the smtp library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 25,465,587 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=domain.com <target>

Default Option Used in script:
nmap  -sV -p 25,465,587 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-25,465,587[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="25,465,587"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-ntlm-info -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-ntlm-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smtp-open-relay

Script types: portrule
Categories: discovery, intrusive, external
Download: http://nmap.org/svn/scripts/smtp-open-relay.nse

User Summary
Attempts to relay mail by issuing a predefined combination of SMTP commands. The goal of this script
is to tell if a SMTP server is vulnerable to mail relaying.
An SMTP server that works as an open relay, is a email server that does not verify if the user is
authorised to send email from the specified email address. Therefore, users would be able to send
email originating from any third-party email address that they want.
The checks are done based in combinations of MAIL FROM and RCPT TO commands. The list is hardcoded
in the source file. The script will output all the working combinations that the server allows
if nmap is in verbose mode otherwise the script will print the number of successful tests. The script
will not output if the server requires authentication.
If debug is enabled and an error occurs while testing the target host, the error will be printed with
the list of any combinations that were found prior to the error.


Script Arguments
smtp-open-relay.ip
Use this to change the IP address to be used (default is the target IP address)
smtp-open-relay.to
Define the destination email address to be used (without the domain, default is relaytest)
smtp.domain
or smtp-open-relay.domain Define the domain to be used in the anti-spam tests and EHLO command (default is nmap.scanme.org)
smtp-open-relay.from
Define the source email address to be used (without the domain, default is antispam)
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smtp-open-relay.nse [--script-args smtp-open-relay.domain=<domain>,smtp-open-relay.ip=<address>,...] -p 25,465,587 <host>

Default Option Used in script:
nmap  -sV -p 25,465,587 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-25,465,587[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="25,465,587"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-open-relay -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-open-relay -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smtp-strangeport

Script types: portrule
Categories: malware, safe
Download: http://nmap.org/svn/scripts/smtp-strangeport.nse

User Summary
Checks if SMTP is running on a non-standard port.
This may indicate that crackers or script kiddies have set up a backdoor on the system to send spam or control the machine.

Example Usage
nmap -sV --script=smtp-strangeport <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script smtp-strangeport'+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script smtp-strangeport -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smtp-vuln-cve2010-4344

Script types: portrule
Categories: exploit, intrusive, vuln
Download: http://nmap.org/svn/scripts/smtp-vuln-cve2010-4344.nse

User Summary
Checks for and/or exploits a heap overflow within versions of Exim prior to version 4.69 (CVE-2010-4344)
and a privilege escalation vulnerability in Exim 4.72 and prior (CVE-2010-4345).
The heap overflow vulnerability allows remote attackers to execute arbitrary code with the privileges of 
he Exim daemon (CVE-2010-4344). If the exploit fails then the Exim smtpd child will be killed (heap corruption).
The script also checks for a privilege escalation vulnerability that affects Exim version 4.72 and prior.
The vulnerability allows the exim user to gain root privileges by specifying an alternate configuration file
using the -C option (CVE-2010-4345).
The smtp-vuln-cve2010-4344.exploit script argument will make the script try to exploit the vulnerabilities,
by sending more than 50MB of data, it depends on the message size limit configuration option of the Exim server. If the exploit succeed the exploit.cmd or smtp-vuln-cve2010-4344.cmd script arguments can be used to run an arbitrary command on the remote system, under the Exim user privileges. If this script argument is set then it will enable the smtp-vuln-cve2010-4344.exploit argument.
To get the appropriate debug messages for this script, please use -d2.


Script Arguments
smtp.domain
Define the domain to be used in the SMTP EHLO command.
exploit.cmd
or smtp-vuln-cve2010-4344.cmd An arbitrary command to run under the Exim user privileges on the remote system. If this argument is set then, it will enable the smtp-vuln-cve2010-4344.exploit argument.
smtp-vuln-cve2010-4344.mailto
Define the destination email address to be used.
smtp-vuln-cve2010-4344.exploit
The script will force the checks, and will try to exploit the Exim SMTP server.
smtp-vuln-cve2010-4344.mailfrom
Define the source email address to be used.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script=smtp-vuln-cve2010-4344 --script-args="smtp-vuln-cve2010-4344.exploit" -pT:25,465,587 <host>
nmap --script=smtp-vuln-cve2010-4344 --script-args="exploit.cmd='uname -a'" -pT:25,465,587 <host>

Default Option Used in script:
nmap  -sV -p 25,465,587 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-25,465,587[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="25,465,587"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-vuln-cve2010-4344 -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-vuln-cve2010-4344 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smtp-vuln-cve2011-1720

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/smtp-vuln-cve2011-1720.nse

User Summary
Checks for a memory corruption in the Postfix SMTP server when it uses Cyrus SASL library authentication mechanisms
(CVE-2011-1720). This vulnerability can allow denial of service and possibly remote code execution.

Script Arguments
smtp.domain
Define the domain to be used in the SMTP EHLO command.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script=smtp-vuln-cve2011-1720 --script-args='smtp.domain=<domain>' -pT:25,465,587 <host>

Default Option Used in script:
nmap  -sV -p 25,465,587 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-25,465,587[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="25,465,587"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-vuln-cve2011-1720 -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-vuln-cve2011-1720 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smtp-vuln-cve2011-1764

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/smtp-vuln-cve2011-1764.nse

User Summary
Checks for a format string vulnerability in the Exim SMTP server (version 4.70 through 4.75)
with DomainKeys Identified Mail (DKIM) support (CVE-2011-1764). The DKIM logging mechanism did
not use format string specifiers when logging some parts of the DKIM-Signature header field.
A remote attacker who is able to send emails, can exploit this vulnerability and execute arbitrary
code with the privileges of the Exim daemon.


Script Arguments
smtp-vuln-cve2011-1764.mailto
Define the destination email address to be used.
smtp.domain
Define the domain to be used in the SMTP EHLO command.
smtp-vuln-cve2011-1764.mailfrom
Define the source email address to be used.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script=smtp-vuln-cve2011-1764 -pT:25,465,587 <host>

Default Option Used in script:
nmap  -sV -p 25,465,587 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-25,465,587[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="25,465,587"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-vuln-cve2011-1764 -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smtp-vuln-cve2011-1764 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smtp(host_ip,desc)
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