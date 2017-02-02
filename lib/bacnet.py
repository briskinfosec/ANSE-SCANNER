def bacnet(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for BACNet Devices
    \t[1] bacnet-info \n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File bacnet-info

Script types: portrule
Categories: discovery, version
Download: http://nmap.org/svn/scripts/bacnet-info.nse

User Summary
Discovers and enumerates BACNet Devices collects device information based off standard requests.
In some cases, devices may not strictly follow the specifications, or may comply with older versions of the specifications,
and will result in a BACNET error response. Presence of this error positively identifies the device as a BACNet device,
but no enumeration is possible.

Note: Requests and responses are via UDP 47808, ensure scanner will receive UDP 47808 source and destination responses.
http://digitalbond.com
Example Usage
nmap --script bacnet-info -sU -p 47808 <host>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-47808[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="47808"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script bacnet-info -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            bacnet(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script bacnet-info -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            bacnet(host_ip,desc)      
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