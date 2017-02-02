def acarsd(host_ip,desc):
    import banner
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for ACARS (Aircraft Communication Addressing and Reporting System)
    [1] acarsd-info
    [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File acarsd-info
 Script types: portrule
 Categories: safe, discovery
 Download: http://nmap.org/svn/scripts/acarsd-info.nse
 User Summary
 Retrieves information from a listening acarsd daemon. 
 Acarsd decodes ACARS (Aircraft Communication Addressing and Reporting System) data in real time. 
 The information retrieved by this script includes the daemon version, API version, administrator e-mail 
 address and listening frequency.
 For more information about acarsd, see:
 http://www.acarsd.org/
 Script Arguments
 acarsd-info.timeout
 Set the timeout in seconds. The default value is 10.
 acarsd-info.bytes
 Set the number of bytes to retrieve. The default value is 512.
 Example Usage
 nmap --script acarsd-info --script-args "acarsd-info.timeout=10,acarsd-info.bytes=512" -p <port> <host>
 
 Default Option Used in tool:
 nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-2202 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2022"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script acarsd-info '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            acarsd(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script acarsd-info -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            acarsd(host_ip,desc)
        else:
            sys.exit(exit_msg)
    elif option == "0":
        from ANSE import  service_scan
        service_scan(host_ip,desc)
    else :
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)