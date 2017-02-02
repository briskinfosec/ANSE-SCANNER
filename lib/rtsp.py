def rtsp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for RTSP (real time streaming protocol) server:
    \t[1] rtsp-methods\n\t[2] rtsp-url-brute\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rtsp-methods

Script types: portrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/rtsp-methods.nse

User Summary
Determines which methods are supported by the RTSP (real time streaming protocol) server.

Script Arguments
rtsp-methods.path
the path to query, defaults to "*" which queries the server itself, rather than a specific url.

Example Usage
nmap -p 554 --script rtsp-methods <ip>

Default Option Used in script:
nmap -sV -p 554 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-554[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="554"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rtsp-methods -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rtsp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rtsp-methods -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rtsp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rtsp-url-brute

Script types: portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/rtsp-url-brute.nse

User Summary
Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras.
The script attempts to discover valid RTSP URLs by sending a DESCRIBE request for each URL in the dictionary. It then parses the response, based on which it determines whether the URL is valid or not.

Script Arguments
rtsp-url-brute.urlfile
sets an alternate URL dictionary file
rtsp-url-brute.threads
sets the maximum number of parallel threads to run

Example Usage
nmap --script rtsp-url-brute -p 554 <ip>

Default Option Used in script:
nmap -sV -p 554 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-554[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="554"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rtsp-url-brute -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rtsp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script rtsp-url-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rtsp(host_ip,desc)
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