def membase(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Couchbase Membase servers:
      [1]  membase-brute
      [2] membase-http-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File membase-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/membase-brute.nse

User Summary
Performs brute force password auditing against Couchbase Membase servers.

Script Arguments
membase-brute.bucketname

if specified, password guessing is performed only against this bucket.
creds.[service], creds.global
See the documentation for the creds library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
membase.authmech
See the documentation for the membase library.

Example Usage
nmap -p 11211 --script membase-brute

Default Option Used in script:
nmap  -p  11211  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-11211[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="11211"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script membase-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            membase(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script membase-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            membase(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File membase-http-info

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/membase-http-info.nse

User Summary
Retrieves information (hostname, OS, uptime, etc.) from the CouchBase Web Administration port.
The information retrieved by this script does not require any credentials.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -p 8091 <ip> --script membase-http-info


Default Option Used in script:
nmap  -p  8091  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-8091[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8091"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script membase-http-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            membase(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script membase-http-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            membase(host_ip,desc)
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