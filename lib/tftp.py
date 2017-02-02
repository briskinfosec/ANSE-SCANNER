def tftp(host_ip,desc) :
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for TFTP (trivial file transfer protocol):
    \t[1] tftp-enum\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File tftp-enum

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/tftp-enum.nse

User Summary
Enumerates TFTP (trivial file transfer protocol) filenames by testing for a list of common ones.
TFTP doesn't provide directory listings. This script tries to retrieve filenames from a list. The list is composed of static names from the file tftplist.txt, plus configuration filenames for Cisco devices that change based on the target address, of the form A.B.C.X-confg for an IP address A.B.C.D and for X in 0 to 255.
Use the tftp-enum.filelist script argument to search for other static filenames.
This script is a reimplementation of tftptheft from http://code.google.com/p/tftptheft/.

Script Arguments
filelist
- file name with list of filenames to enumerate at tftp server

Example Usage
nmap -sU -p 69 --script tftp-enum.nse --script-args="tftp-enum.filelist=customlist.txt" <host>

Default Option Used in script:
nmap  -sV -sU -p 69 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-69[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="69"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script  tftp-enum -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            tftp(host_ip,desc) 
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  tftp-enum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            tftp(host_ip,desc) 
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