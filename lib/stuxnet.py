def stuxnet(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Stuxnet worms:
    \t[1] stuxnet-detect\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File stuxnet-detect

Script types: hostrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/stuxnet-detect.nse

User Summary
Detects whether a host is infected with the Stuxnet worm (http://en.wikipedia.org/wiki/Stuxnet).
An executable version of the Stuxnet infection will be downloaded if a format for the filename is given on the command line.

Script Arguments
stuxnet-detect.save

Path to save Stuxnet executable under, with %h replaced by the host's IP address, and %v replaced by the version of Stuxnet.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script stuxnet-detect -p 445 <host>>

Default Option Used in script:
nmap  -sV -p 445 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  stuxnet-detect -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            stuxnet(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"     
            subprocess.call('nmap -sV  --script  stuxnet-detect -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            stuxnet(host_ip,desc)
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