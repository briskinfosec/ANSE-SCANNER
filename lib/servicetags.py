def servicetags(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Sun Service Tags service agent :
    \t[1] servicetags\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File servicetags

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/servicetags.nse

User Summary
Attempts to extract system information (OS, hardware, etc.) from the Sun Service Tags service agent (UDP port 6481).
Based on protocol specs from http://arc.opensolaris.org/caselog/PSARC/2006/638/stdiscover_protocolv2.pdf http://arc.opensolaris.org/caselog/PSARC/2006/638/stlisten_protocolv2.pdf http://arc.opensolaris.org/caselog/PSARC/2006/638/ServiceTag_API_CLI_v07.pdf

Example Usage
nmap -sU -p 6481 --script=servicetags <target>

Default Option Used in script:
nmap -sV -sU -p 6481 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-6481[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="6481"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script servicetags -p'+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            servicetags(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script servicetags -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            servicetags(host_ip,desc)
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