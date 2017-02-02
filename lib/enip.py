def enip(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Wireshark dissector:
      [1] enip-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File enip-info

Script types: portrule
Categories: discovery, version
Download: http://nmap.org/svn/scripts/enip-info.nse

User Summary
This NSE script is used to send a EtherNet/IP packet to a remote device that has TCP 44818 open. The script will
send a Request Identity Packet and once a response is received, it validates that it was a proper response to the
command that was sent, and then will parse out the data. Information that is parsed includes Vendor ID, Device Type,
Product name, Serial Number, Product code,Revision Number, as well as the Device IP.

Example Usage
nmap --script enip-info -sU  -p 44818 <host>s>

Default Option Used in script:
nmap  -sU -p  44818 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-44818[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="44818"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script enip-info  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            enip(host_ip,desc)   
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script enip-info  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            enip(host_ip,desc)    
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