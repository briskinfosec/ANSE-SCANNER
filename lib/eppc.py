def eppc(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Apple Remote Event protocol:
      [1] eppc-enum-processes
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File eppc-enum-processes

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/eppc-enum-processes.nse

User Summary
Attempts to enumerate process info over the Apple Remote Event protocol. When accessing an application over
the Apple Remote Event protocol the service responds with the uid and pid of the application, if it is running,
prior to requesting authentication.

Example Usage
nmap -p 3031 <ip> --script eppc-enum-processes

Default Option Used in script:
nmap -p 3031 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3031[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3031"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script eppc-enum-processes  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            eppc(host_ip,desc)    
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script eppc-enum-processes  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            eppc(host_ip,desc)     
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