def nexpose(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Nexpose:
    \t[1] nexpose-brute\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File nexpose-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/nexpose-brute.nse

User Summary
Performs brute force password auditing against a Nexpose vulnerability scanner using the API 1.1.
As the Nexpose application enforces account lockout after 4 incorrect login attempts, the script performs only 3 guesses per default. This can be altered by supplying the brute.guesses argument a different value or 0 (zero) to guess the whole dictionary.

Script Arguments
creds.[service], creds.global
See the documentation for the creds library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap --script nexpose-brute -p 3780 <ip>>

Default Option Used in script:
nmap -sV -p 3780 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3780[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3780"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script nexpose-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nexpose(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script nexpose-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nexpose(host_ip,desc)
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