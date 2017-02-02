def mikrotik(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Mikrotik RouterOS devices:
      [1] mikrotik-routeros-brute
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mikrotik-routeros-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/mikrotik-routeros-brute.nse

User Summary
Performs brute force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled.

Additional information:
    http://wiki.mikrotik.com/wiki/API

Script Arguments
mikrotik-routerous-brute.threads
sets the number of threads. Default: 1
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries,
brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap -p8728 --script mikrotik-routeros-brute <target>

Default Option Used in script:
nmap  -p  8728  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-8728[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8728"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mikrotik-routeros-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mikrotik(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mikrotik-routeros-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mikrotik(host_ip,desc)
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