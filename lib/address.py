def address(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script
    [1] address-info
    [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File address-info

Script types: hostrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/address-info.nse

User Summary
Shows extra information about IPv6 addresses, such as embedded MAC or IPv4 addresses when available.
for example some IPv6 addresses encode an IPv4 address or MAC address.
This script can decode these address formats:
    IPv4-compatible IPv6 addresses,
    IPv4-mapped IPv6 addresses,
    Teredo IPv6 addresses,
    6to4 IPv6 addresses,
    IPv6 addresses using an EUI-64 interface ID,
    IPv4-embedded IPv6 addresses,
    IPv4-translated IPv6 addresses and
    ISATAP Modified EUI-64 IPv6 addresses.
Example Usage
nmap -sV -sC <target>

Default Option Used in tool:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        arg=input("Enter argument if you need or press just enter:")
        file_name=input("Enter your file name to save:")
        output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
        subprocess.call('nmap --script address-info '+arg+' '+host_ip+' '+output,shell=True)
        address(host_ip,desc)
    elif option == "0":
        from ANSE  import service_scan
        service_scan(host_ip,desc)
    else:
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)