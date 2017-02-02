def ganglia(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Ganglia Monitoring Daemon:
     [1] ganglia-info
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ganglia-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/ganglia-info.nse

User Summary
Retrieves system information (OS version, available memory, etc.) from a listening Ganglia Monitoring Daemon or Ganglia Meta Daemon.
Ganglia is a scalable distributed monitoring system for high-performance computing systems such as clusters and Grids.
The information retrieved includes HDD size, available memory, OS version, architecture (and more) from each of the systems in
each of the clusters in the grid.

Script Arguments
ganglia-info.bytes
Set the number of bytes to retrieve. The default value is 1000000. This should be enough for a grid of more than 100 hosts.
About 5KB-10KB of data is returned for each host in the cluster.
ganglia-info.timeout
Set the timeout in seconds. The default value is 30.
slaxml.debug
See the documentation for the slaxml library.

Example Usage
nmap --script ganglia-info --script-args ganglia-info.timeout=60,ganglia-info.bytes=1000000 -p <port> <target>>

Default Option Used in script:
nmap  -p [all-port] --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-all-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ganglia-info'+' '+arg+' '+host_ip+' '+output,shell=True)
            ganglia(host_ip,desc)     
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ganglia-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ganglia(host_ip,desc)     
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
        