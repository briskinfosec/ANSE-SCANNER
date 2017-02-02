def snmp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for SNMP Service:
     [1] snmp-brute
     [2] snmp-hh3c-logins
     [3] snmp-info
     [4] snmp-interfaces
     [5] snmp-ios-config
     [6] snmp-netstat
     [7] snmp-processes
     [8] snmp-sysdescr
     [9] snmp-win32-services
    [10] snmp-win32-shares
    [11] snmp-win32-software
    [12] snmp-win32-users
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/snmp-brute.nse

User Summary
Attempts to find an SNMP community string by brute force guessing.
This script opens a sending socket and a sniffing pcap socket in parallel threads.
The sending socket sends the SNMP probes with the community strings, while the pcap 
ocket sniffs the network for an answer to the probes. If valid community strings are found,
they are added to the creds database and reported in the output.
The script takes the snmp-brute.communitiesdb argument that allows the user to define the file
that contains the community strings to be used. If not defined, the default wordlist used to bruteforce
the SNMP community strings is nselib/data/snmpcommunities.lst. In case this wordlist does not exist,
the script falls back to nselib/data/passwords.lst
No output is reported if no valid account is found.

Script Arguments
snmp-brute.communitiesdb
The filename of a list of community strings to try.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script snmp-brute'+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script snmp-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-hh3c-logins

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/snmp-hh3c-logins.nse

User Summary
Attempts to enumerate Huawei / HP/H3C Locally Defined Users through the hh3c-user.mib OID
For devices running software released pre-Oct 2012 only an SNMP read-only string is required to
access the OID. Otherwise a read-write string is required.
Output is 'username - password - level: {0|1|2|3}'
Password may be in cleartext, ciphertext or sha256 Levels are from 0 to 3 with 0 being the lowest security level

Script Arguments
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script snmp-hh3c-logins --script-args snmpcommunity=<community> <target>

Default Option Used in script:
nmap  -sV -sU -p 161--script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-hh3c-logins -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-hh3c-logins -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-info

Script types: portrule
Categories: default, version, safe
Download: http://nmap.org/svn/scripts/snmp-info.nse

User Summary
Extracts basic information from an SNMPv3 GET request. The same probe is used here as in the service version detection scan.

Script Arguments
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sV <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script snmp-info'+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script snmp-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-interfaces

Script types: prerule, portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/snmp-interfaces.nse

User Summary
Attempts to enumerate network interfaces through SNMP.
This script can also be run during Nmap's pre-scanning phase and can attempt to add the SNMP server's
interface addresses to the target list. The script argument snmp-interfaces.host is required to know what host to probe.
To specify a port for the SNMP server other than 161, use snmp-interfaces.port. When run in this way,
the script's output tells how many new targets were successfully added.

Script Arguments
snmp-interfaces.host
Specifies the SNMP server to probe when running in the "pre-scanning phase".
snmp-interfaces.port
The optional port number corresponding to the host script argument. Defaults to 161.
max-newtargets, newtargets
See the documentation for the target library.
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script=snmp-interfaces <target>

Default Option Used in script:
nmap  -sV -sU -p 161--script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-interfaces -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-interfaces -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-ios-config

Script types: portrule
Categories: intrusive
Download: http://nmap.org/svn/scripts/snmp-ios-config.nse

User Summary
Attempts to downloads Cisco router IOS configuration files using SNMP RW (v1) and display or save them.

Script Arguments
snmp-ios-config.tftproot
If set, specifies to what directory the downloaded config should be saved
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script snmp-ios-config --script-args snmpcommunity=<community> <target>

Default Option Used in script:
nmap  -sV -sU -p 161--script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-ios-config -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-ios-config -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-netstat

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/snmp-netstat.nse

User Summary
Attempts to query SNMP for a netstat like output. The script can be used to identify and automatically
add new targets to the scan by supplying the newtargets script argument.

Script Arguments
max-newtargets, newtargets
See the documentation for the target library.
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script=snmp-netstat <target>

Default Option Used in script:
nmap  -sV -sU -p 161--script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-netstat -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-netstat -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-processes

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/snmp-processes.nse

User Summary
Attempts to enumerate running processes through SNMP.

Script Arguments
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script=snmp-processes <target>

Default Option Used in script:
nmap  -sV -sU -p 161--script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-processes -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-processes -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-sysdescr
Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/snmp-sysdescr.nse

User Summary
Attempts to extract system information from an SNMP version 1 service.

Script Arguments
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script snmp-sysdescr <target>

Default Option Used in script:
nmap  -sV -sU -p 161 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-sysdescr -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-sysdescr -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-win32-services

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/snmp-win32-services.nse

User Summary
Attempts to enumerate Windows services through SNMP.

Script Arguments
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script=snmp-win32-services <target>

Default Option Used in script:
nmap  -sV -sU -p 161 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-win32-services -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-win32-services -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "10":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-win32-shares

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/snmp-win32-shares.nse

User Summary
Attempts to enumerate Windows Shares through SNMP.

Script Arguments
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script=snmp-win32-shares <target>
nmap -sU -p 161 --script=snmp-win32-shares <target>

Default Option Used in script:
nmap  -sV -sU -p 161 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-win32-shares -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-win32-shares -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "11":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-win32-software

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/snmp-win32-software.nse

User Summary
Attempts to enumerate installed software through SNMP.

Script Arguments
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script=snmp-win32-software <target>

Default Option Used in script:
nmap  -sV -sU -p 161 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-win32-software -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-win32-software -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "12":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File snmp-win32-users

Script types: portrule
Categories: default, auth, safe
Download: http://nmap.org/svn/scripts/snmp-win32-users.nse

User Summary
Attempts to enumerate Windows user accounts through SNMP

Script Arguments
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -sU -p 161 --script=snmp-win32-users <target

Default Option Used in script:
nmap  -sV -sU -p 161 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-161[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="161"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script snmp-win32-users -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU  --script snmp-win32-users -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            snmp(host_ip,desc)
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