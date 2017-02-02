def riak(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Basho Riak distributed database:
    \t[1] riak-http-info\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File riak-http-info

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/riak-http-info.nse

User Summary
Retrieves information (such as node name and architecture) from a Basho Riak distributed database using the HTTP protocol.

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.

Example Usage
nmap -p 8098 <ip> --script riak-http-info

Default Option Used in script:
nmap -sV -p 8098 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-8098[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8098"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script riak-http-info -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            riak(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script riak-http-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            riak(host_ip,desc)
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