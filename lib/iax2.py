def iax2(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Asterisk IAX2 protocol:
      [1] iax2-brute
      [2] iax2-version
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File iax2-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/iax2-brute.nse

User Summary
Performs brute force password auditing against the Asterisk IAX2 protocol. Guessing fails when a large number of attempts is made due to the maxcallnumber limit (default 2048). In case your getting "ERROR: Too many retries, aborted ..." after a while, this is most likely what's happening. In order to avoid this problem try: - reducing the size of your dictionary - use the brute delay option to introduce a delay between guesses - split the guessing up in chunks and wait for a while between them

Script Arguments
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap -sU -p 4569 <ip> --script iax2-brute

Default Option Used in script:
nmap -sU -p 4569 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-4569[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="4569"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script iax2-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            iax2(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script iax2-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            iax2(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File iax2-version

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/iax2-version.nse

User Summary
Detects the UDP IAX2 service.
The script sends an Inter-Asterisk eXchange (IAX) Revision 2 Control Frame POKE request and checks for a proper response. This protocol is used to enable VoIP connections between servers as well as client-server communication.

Example Usage
nmap -sU -sV -p 4569 <target>

Default Option Used in script:
nmap -sU -sV -p 4569 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-4569[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="4569"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU -sV--script iax2-version -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            iax2(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU -sV --script iax2-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            iax2(host_ip,desc)
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