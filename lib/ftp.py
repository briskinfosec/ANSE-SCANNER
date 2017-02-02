def ftp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for FTP service:
      [1] ftp-anon
      [2] ftp-bounce
      [3] ftp-brute
      [4] ftp-libopie
      [5] ftp-proftpd-backdoor
      [6] ftp-vsftpd-backdoor
      [7] ftp-vuln-cve2010-4221
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ftp-anon

Script types: portrule
Categories: default, auth, safe
Download: http://nmap.org/svn/scripts/ftp-anon.nse

User Summary
Checks if an FTP server allows anonymous logins.
If anonymous is allowed, gets a directory listing of the root directory and highlights writeable files.

Script Arguments
ftp-anon.maxlist
The maximum number of files to return in the directory listing. By default it is 20, or unlimited if verbosity
is enabled.Use a negative number to disable the limit, or 0 to disable the listing entirely.

Example Usage
nmap -sV -sC <target>

Default Option Used in script:
nmap  -p 21 -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-21[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="21"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ftp-anon -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ftp-anon -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)   
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ftp-bounce

Script types: portrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/ftp-bounce.nse

User Summary
Checks to see if an FTP server allows port scanning using the FTP bounce method.

Script Arguments
ftp-bounce.password
Password to log in with. Default "IEUser@".
ftp-bounce.username
Username to log in with. Default "anonymous".
ftp-bounce.checkhost
Host to try connecting to with the PORT command. Default: scanme.nmap.org

Example Usage
nmap -sV -sC <target>

Default Option Used in script:
nmap  -p 21 -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-21[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="21"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ftp-bounce -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ftp-bounce -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)   
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ftp-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/ftp-brute.nse

User Summary
Performs brute force password auditing against FTP servers.
Based on old ftp-brute.nse script by Diman Todorov, Vlatko Kosturjak and Ron Bowes.

Script Arguments
ftp-brute.timeout
the amount of time to wait for a response on the socket. Lowering this value may result in a higher throughput 
or servers having a delayed response on incorrect login attempts. (default: 5s)
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries,
brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap --script ftp-brute -p 21 <host>
This script uses brute library to perform password
guessing.

Default Option Used in script:
nmap  -p 21 -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-21[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="21"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ftp-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ftp-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)   
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ftp-libopie

Script types: portrule
Categories: vuln, intrusive
Download: http://nmap.org/svn/scripts/ftp-libopie.nse

User Summary
Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow)

Script Arguments
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script=ftp-libopie <target>

Default Option Used in script:
nmap  -p 21 -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-21[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="21"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ftp-libopie -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ftp-libopie -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)   
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ftp-proftpd-backdoor

Script types: portrule
Categories: exploit, intrusive, malware, vuln
Download: http://nmap.org/svn/scripts/ftp-proftpd-backdoor.nse

User Summary
Tests for the presence of the ProFTPD 1.3.3c backdoor reported as OSVDB-ID 69562.This script attempts to exploit
the backdoor using the innocuous id command by default, but that can be changed with the ftp-proftpd-backdoor.cmd script
argument.

Script Arguments
ftp-proftpd-backdoor.cmd
Command to execute in shell (default is id).

Example Usage
nmap --script ftp-proftpd-backdoor -p 21 <host>

Default Option Used in script:
nmap  -p 21 -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-21[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="21"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ftp-proftpd-backdoor -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ftp-proftpd-backdoor -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)   
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ftp-vsftpd-backdoor

Script types: portrule
Categories: exploit, intrusive, malware, vuln
Download: http://nmap.org/svn/scripts/ftp-vsftpd-backdoor.nse

User Summary
Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04 (CVE-2011-2523). This script attempts to
exploit the backdoor using the innocuous id command by default, but that can be changed with the exploit.cmd or
ftp-vsftpd-backdoor.cmd script arguments.

References:
http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=CVE-2011-2523

Script Arguments
exploit.cmd
or ftp-vsftpd-backdoor.cmd Command to execute in shell (default is id).
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script ftp-vsftpd-backdoor -p 21 <host>

Default Option Used in script:
nmap  -p 21 -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-21[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="21"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ftp-vsftpd-backdoor -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ftp-vsftpd-backdoor -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)   
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ftp-vuln-cve2010-4221

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/ftp-vuln-cve2010-4221.nse

User Summary
Checks for a stack-based buffer overflow in the ProFTPD server, version between 1.3.2rc3 and 1.3.3b.
By sending a large number of TELNET_IAC escape sequence, the proftpd process miscalculates the buffer length,
and a remote attacker will be able to corrupt the stack and execute arbitrary code within the context of the
proftpd process (CVE-2010-4221). Authentication is not required to exploit this vulnerability.

Reference:
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4221
http://www.exploit-db.com/exploits/15449/
http://www.metasploit.com/modules/exploit/freebsd/ftp/proftp_telnet_iac

Script Arguments
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script ftp-vuln-cve2010-4221 -p 21 <host>

Default Option Used in script:
nmap  -p 21 -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-21[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="21"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ftp-vuln-cve2010-4221 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)  
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ftp-vuln-cve2010-4221 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ftp(host_ip,desc)   
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
        