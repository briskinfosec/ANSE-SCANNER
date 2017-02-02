def omp2(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for OpenVAS manager using OMPv2:
    \t[1] omp2-brute\n\t[2] omp2-enum-targets\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File omp2-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/omp2-brute.nse

User Summary
Performs brute force password auditing against the OpenVAS manager using OMPv2.

Script Arguments
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
omp2.password, omp2.username
See the documentation for the omp2 library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap -p 9390 --script omp2-brute <target>


Default Option Used in script:
nmap -sV -p 9390 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-9390[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="9390"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script omp2-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            omp2(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script omp2-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            omp2(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File omp2-enum-targets

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/omp2-enum-targets.nse

User Summary
Attempts to retrieve the list of target systems and networks from an OpenVAS Manager server.
The script authenticates on the manager using provided or previously cracked credentials and gets the list of defined targets for each account.
These targets will be added to the scanning queue in case newtargets global variable is set.

Script Arguments
max-newtargets, newtargets
See the documentation for the target library.
omp2.password, omp2.username
See the documentation for the omp2 library.

Example Usage
    nmap -p 9390 --script omp2-enum-targets,omp2-enum-targets <target>
    nmap -p 9390 --script omp2-enum-targets --script-args omp2.username=admin,omp2.password=secret <target>


Default Option Used in script:
nmap -sV -p 9390 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-9390[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="9390"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script omp2-enum-targets -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            omp2(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script omp2-enum-targets -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            omp2(host_ip,desc)
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