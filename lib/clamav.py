def clamav(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for ClamAV servers
      [1] clamav-exec
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File clamav-exec
Script types: portrule
Categories: exploit, vuln
Download: http://nmap.org/svn/scripts/clamav-exec.nse

User Summary
Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution.
ClamAV server 0.99.2, and possibly other previous versions, allow the execution of dangerous service commands
without authentication. Specifically, the command 'SCAN' may be used to list system files and the command 'SHUTDOWN'
shut downs the service. This vulnerability was discovered by Alejandro Hernandez (nitr0us).
This script without arguments test the availability of the command 'SCAN'.

Script Arguments
clamav-exec.scandb
Database to file list.
clamav-exec.cmd
Command to execute. Option: scan and shutdown
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script clamav-exec <target>
nmap --script clamav-exec --script-args cmd='scan',scandb='files.txt' <target>
nmap --script clamav-exec --script-args cmd='shutdown' <target>

Default Option Used in script:
nmap --script [script name] -p 3310 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3310[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3310"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script clamav-execute -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            clamav(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script clamav-exec -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            clamav(host_ip,desc)      
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