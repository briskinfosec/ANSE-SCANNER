def p2p(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for  Conficker's peer to peer communication:
    \t[1] p2p-conficker\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File p2p-conficker

Script types: hostrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/p2p-conficker.nse

User Summary
Checks if a host is infected with Conficker.C or higher, based on Conficker's peer to peer communication.

Script Arguments
realip
An IP address to use in place of the one known by Nmap.
checkall
If set to 1 or true, attempt to communicate with every open port.
checkconficker
If set to 1 or true, the script will always run on active hosts, it doesn't matter if any open ports were detected.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
# Run the scripts against host(s) that appear to be Windows
nmap --script p2p-conficker,smb-os-discovery,smb-check-vulns --script-args=safe=1 -T4 -vv -p445 <host>
sudo nmap -sU -sS --script p2p-conficker,smb-os-discovery,smb-check-vulns --script-args=safe=1 -vv -T4 -p U:137,T:139 <host>

# Run the scripts against all active hosts (recommended)
nmap -p139,445 -vv --script p2p-conficker,smb-os-discovery,smb-check-vulns --script-args=checkconficker=1,safe=1 -T4 <host>

# Run scripts against all 65535 ports (slow)
nmap --script p2p-conficker,smb-os-discovery,smb-check-vulns -p- --script-args=checkall=1,safe=1 -vv -T4 <host>

# Base checks on a different ip address (NATed)
nmap --script p2p-conficker,smb-os-discovery -p445 --script-args=realip=\"192.168.1.65\" -vv -T4 <host>

Default Option Used in script:
nmap -sV -T4 -p 139,445 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option(Recommended)-port-139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -T4 -sV --script p2p-conficker -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            p2p(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script p2p-conficker -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            p2p(host_ip,desc)
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