def hadoop(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Apache Hadoop DataNode HTTP status page:
      [1] hadoop-datanode-info
      [2] hadoop-jobtracker-info
      [3] hadoop-namenode-info
      [4] hadoop-secondary-namenode-info
      [5] hadoop-tasktracker-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hadoop-datanode-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/hadoop-datanode-info.nse

User Summary
Discovers information such as log directories from an Apache Hadoop DataNode HTTP status page.

Information gathered:
Log directory (relative to http://host:port/)

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script hadoop-datanode-info.nse -p 50075 host

Default Option Used in script:
nmap  -p 50075 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-50075[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="50075"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script hadoop-datanode-info-p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script hadoop-datanode-info-p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)  
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hadoop-jobtracker-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/hadoop-jobtracker-info.nse

User Summary
Retrieves information from an Apache Hadoop JobTracker HTTP status page.

Script Arguments
hadoop-jobtracker-info.userinfo
Retrieve user history info. Default: false
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
max-newtargets, newtargets
See the documentation for the target library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script hadoop-jobtracker-info [--script-args=hadoop-jobtracker-info.userinfo] -p 50030 host


Default Option Used in script:
nmap  -p 50030 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-50030[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="50030"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script hadoop-jobtracker-in -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script hadoop-jobtracker-in -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hadoop-namenode-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/hadoop-namenode-info.nse

User Summary
Retrieves information from an Apache Hadoop NameNode HTTP status page.

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
nmap --script hadoop-namenode-info -p 50070 host


Default Option Used in script:
nmap  -p 50070 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-50070[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="50070"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script hadoop-namenode-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script hadoop-namenode-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hadoop-secondary-namenode-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/hadoop-secondary-namenode-info.nse

User Summary
Retrieves information from an Apache Hadoop secondary NameNode HTTP status page.

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
nmap --script  hadoop-secondary-namenode-info -p 50090 host

Default Option Used in script:
nmap  -p 50090 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-50090[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="50090"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script hadoop-secondary-namenode-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script hadoop-secondary-namenode-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc) 
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File hadoop-tasktracker-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/hadoop-tasktracker-info.nse

User Summary
Retrieves information from an Apache Hadoop TaskTracker HTTP status page.

Information gathered:
    Hadoop version
    Hadoop Compile date
    Log directory (relative to http://host:port/)

Script Arguments
slaxml.debug
See the documentation for the slaxml library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script hadoop-tasktracker-info -p 50060 host


Default Option Used in script:
nmap  -p 50090 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-50090[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="50090"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script hadoop-tasktracker-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script hadoop-tasktracker-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            hadoop(host_ip,desc) 
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
        