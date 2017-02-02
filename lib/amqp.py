def amqp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for AMQP (advanced message queuing protocol) server
    [1] amqp-info
    [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File amqp-info

Script types: portrule
Categories: default, discovery, safe, version
Download: http://nmap.org/svn/scripts/amqp-info.nse

User Summary
Gathers information (a list of all server properties) from an AMQP (advanced message queuing protocol) server.
See http://www.rabbitmq.com/extensions.html for details on the server-properties field.

Script Arguments
amqp.version
Can be used to specify the client version to use (currently, 0-8, 0-9 or 0-9-1)

Example Usage
nmap --script amqp-info -p5672 <target>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-5672 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="5672"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  amqp-info -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            amqp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script  amqp-info  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            amqp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg) 
    elif option == "0":
        from ANSE import service_scan
        service_scan(host_ip,desc)
    else:
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)
