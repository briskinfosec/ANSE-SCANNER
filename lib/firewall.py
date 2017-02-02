def firewall(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for firewall:
      [1] firewalk
      [2] firewall-bypass
      [3] flume-master-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File firewalk

Script types: hostrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/firewalk.nse

User Summary
Tries to discover firewalk rules using an IP TTL expiration technique known as firewalking.
To determine a rule on a given gateway, the scanner sends a probe to a metric located behind the gateway, with a
TTL one higher than the gateway. If the probe is forwarded by the gateway, then we can expect to receive an
ICMP_TIME_EXCEEDED reply from the gateway next hop router, or eventually the metric itself if it is directly connected
to the gateway. Otherwise, the probe will timeout.
It starts with a TTL equals to the distance to the target. If the probe timeout, then it is resent with a TTL decreased by
one. If we get an ICMP_TIME_EXCEEDED, then the scan is over for this probe.
Every "no-reply" filtered TCP and UDP ports are probed. As for UDP scans, this process can be quite slow if lots of ports
are blocked by a gateway close to the scanner.

Script Arguments
firewalk.max-probed-ports
maximum number of ports to probe per protocol. Set to -1 to scan every filtered port.
firewalk.max-retries
the maximum number of allowed retransmissions.
firewalk.recv-timeout
the duration of the packets capture loop (in milliseconds).
firewalk.max-active-probes
maximum number of parallel active probes.
firewalk.probe-timeout
validity period of a probe (in milliseconds).

Example Usage
nmap --script=firewalk --traceroute <host>
nmap --script=firewalk --traceroute --script-args=firewalk.max-retries=1 <host>
nmap --script=firewalk --traceroute --script-args=firewalk.probe-timeout=400ms <host>
nmap --script=firewalk --traceroute --script-args=firewalk.max-probed-ports=7 <host>


Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script firewalk'+' '+arg+' '+host_ip+' '+output,shell=True)
            firewall(host_ip,desc)     
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script firewalk -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            firewall(host_ip,desc)     
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File firewall-bypass

Script types: hostrule
Categories: vuln, intrusive
Download: http://nmap.org/svn/scripts/firewall-bypass.nse

User Summary
Detects a vulnerability in netfilter and other firewalls that use helpers to dynamically open ports for protocols
such as ftp and sip.
The script works by spoofing a packet from the target server asking for opening a related connection to a target port
which will be fulfilled by the firewall through the adequate protocol helper port. The attacking machine should be on
the same network segment as the firewall for this to work. The script supports ftp helper on both IPv4 and IPv6.
Real path filter is used to prevent such attacks.

Script Arguments
firewall-bypass.helper
The helper to use. Defaults to ftp. Supported helpers: ftp (Both IPv4 and IPv6).
firewall-bypass.targetport
Port to test vulnerability on. Target port should be a non-open port. If not given, the script will try to find a filtered or closed port from the port scan results.
firewall-bypass.helperport
If not using the helper's default port.

Example Usage
nmap --script firewall-bypass <target>
nmap --script firewall-bypass --script-args firewall-bypass.helper="ftp", firewall-bypass.targetport=22 <target>


Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script firewall-bypass'+' '+arg+' '+host_ip+' '+output,shell=True)
            firewall(host_ip,desc)     
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script firewall-bypass -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            firewall(host_ip,desc)     
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File flume-master-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/flume-master-info.nse

User Summary
Retrieves information from Flume master HTTP pages.

Information gathered:
    Flume version
    Flume server id
    Zookeeper/Hbase master servers present in configured flows
    Java information
    OS information
    various other local configurations.

If this script is run wth -v, it will output lots more info.
Use the newtargets script argument to add discovered hosts to the Nmap scan queue.

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
nmap --script flume-master-info -p 35871 host

Default Option Used in script:
nmap -p 35871 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-35871[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="35871"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script flume-master-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            firewall(host_ip,desc)   
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script flume-master-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            firewall(host_ip,desc)    
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