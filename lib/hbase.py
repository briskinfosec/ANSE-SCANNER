def hbase(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Apache HBase (Hadoop database) master HTTP status page:
      [1] hbase-master-info
      [2] hbase-region-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hbase-master-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/hbase-master-info.nse

User Summary
Retrieves information from an Apache HBase (Hadoop database) master HTTP status page.

Information gathered:
    Hbase version
    Hbase compile date
    Hbase root directory
    Hadoop version
    Hadoop compile date
    Average load
    Zookeeper quorum server
    Associated region servers

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
max-newtargets, newtargets
See the documentation for the target library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script hbase-master-info -p 60010 host

Default Option Used in script:
nmap  -p 60010 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-60010[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="60010"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script hbase-master-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hbase(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script hbase-master-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hbase(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hbase-region-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/hbase-region-info.nse

User Summary
Retrieves information from an Apache HBase (Hadoop database) region server HTTP status page.

Information gathered:
    HBase version
    HBase compile date
    A bunch of metrics about the state of the region server
    Zookeeper quorum server

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
max-newtargets, newtargets
See the documentation for the target library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script hbase-region-info -p 60030 host

Default Option Used in script:
nmap  -p 60030 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-60030[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="60030"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script hbase-region-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hbase(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script hbase-region-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hbase(host_ip,desc) 
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