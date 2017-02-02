def modbus(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for SCADA Modbus slave ids (sids):
      [1] modbus-discove
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File modbus-discover

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/modbus-discover.nse

User Summary
Enumerates SCADA Modbus slave ids (sids) and collects their device information.
Modbus is one of the popular SCADA protocols. This script does Modbus device information disclosure. It tries to find legal sids 7
(slave ids) of Modbus devices and to get additional information about the vendor and firmware. This script is improvement of modscan
python utility written by Mark Bristow.

Information about MODBUS protocol and security issues:
    MODBUS application protocol specification: http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
    Defcon 16 Modscan presentation: https://www.defcon.org/images/defcon-16/dc16-presentations/defcon-16-bristow.pdf
    Modscan utility is hosted at google code: http://code.google.com/p/modscan/

Script Arguments
  aggressive
- boolean value defines find all or just first sid

Example Usage
    nmap --script modbus-discover.nse --script-args='modbus-discover.aggressive=true' -p 502 <host>

Default Option Used in script:
nmap  -p  502  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-502[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="502"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script modbus-discover -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            modbus(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script modbus-discover -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            modbus(host_ip,desc)
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