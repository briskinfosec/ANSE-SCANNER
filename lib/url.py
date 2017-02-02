def url(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for HTTP traffic:
    \t[1] url-snarf\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File url-snarf

Script types: prerule
Categories: safe
Download: http://nmap.org/svn/scripts/url-snarf.nse

User Summary
Sniffs an interface for HTTP traffic and dumps any URLs, and their originating IP address. Script output differs from other script as URLs are written to stdout directly. There is also an option to log the results to file.
The script can be limited in time by using the timeout argument or run until a ctrl+break is issued, by setting the timeout to 0.

Script Arguments
url-snarf.outfile
filename to which all discovered URLs are written
url-snarf.timeout
runs the script until the timeout is reached. a timeout of 0s can be used to run until ctrl+break. (default: 30s)
url-snarf.interface
interface on which to sniff (overrides -e)
url-snarf.nostdout
doesn't write any output to stdout while running

Example Usage
nmap --script url-snarf -e <interface>

Default Option Used in script:
nmap -sV -e [interface] --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            inter=input("Enter your interface name")
            interface="-e"+' '+inter
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script url-snarf '+' '+interface+' '+arg+' '+host_ip+' '+output,shell=True)
            url(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script url-snarf  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            url(host_ip,desc)
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