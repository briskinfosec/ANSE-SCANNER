def mmouse(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for RPA Tech Mobile Mouse servers:
      [1] mmouse-brute
      [2]  mmouse-exec
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mmouse-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/mmouse-brute.nse
User Summary

Performs brute force password auditing against the RPA Tech Mobile Mouse servers.
The Mobile Mouse server runs on OS X, Windows and Linux and enables remote control of the keyboard and mouse from an iOS device. For more information: http://mobilemouse.com/

Script Arguments
mmouse-brute.timeout
socket timeout for connecting to Mobile Mouse (default 5s)
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap --script mmouse-brute -p 51010 <host>

Default Option Used in script:
nmap  -p  51010  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-51010[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="51010"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mmouse-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mmouse(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mmouse-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mmouse(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mmouse-exec

Script types: portrule
Categories: intrusive
Download: http://nmap.org/svn/scripts/mmouse-exec.nse

User Summary
Connects to an RPA Tech Mobile Mouse server, starts an application and sends a sequence of keys to it. Any application that the user has access to can be started and the key sequence is sent to the application after it has been started.
The Mobile Mouse server runs on OS X, Windows and Linux and enables remote control of the keyboard and mouse from an iOS device. For more information: http://mobilemouse.com/
The script has only been tested against OS X and will detect the remote OS and abort unless the OS is detected as Mac.

Script Arguments
mmouse-exec.application
The application which is to be started at the server
mmouse-exec.delay
Delay in seconds to wait before sending the key sequence. (default: 3 seconds)
mmouse-exec.password
The password needed to connect to the mobile mouse server
mmouse-exec.keys
The key sequence to send to the started application
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -p 51010 <host> --script mmouse-exec \
  --script-args application='/bin/sh',keys='ping -c 5 127.0.0.1'

Default Option Used in script:
nmap  -p  51010  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-51010[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="51010"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mmouse-exec -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mmouse(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mmouse-exec -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mmouse(host_ip,desc)
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
        