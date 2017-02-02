def murmur(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for  Murmur servic:
      [1] distcc-cve2004-2687
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File murmur-version

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/murmur-version.nse
User Summary

Detects the Murmur service (server for the Mumble voice communication client) versions 1.2.X.
The Murmur server listens on a TCP (control) and a UDP (voice) port with the same port number. T
his script activates on both a TCP and UDP port version scan. In both cases probe data is sent only
to the UDP port because it allows for a simple and informative ping command.
The single probe will report on the server version, current user count, maximum users allowed on the server,
and bandwidth used for voice communication. It is used by the Mumble client to ping known Murmur servers.
The IP address from which service detection is being ran will most likely be temporarily banned by the target
Murmur server due to multiple incorrect handshakes (Nmap service probes). This ban makes identifying the service
via TCP impossible in practice, but does not affect the UDP probe used by this script.
It is possible to get a corrupt user count (usually +1) when doing a TCP service scan due to previous service probe
connections affecting the server.
See http://mumble.sourceforge.net/Protocol.

Example Usage
nmap -sV <target>_

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script murmur-version'+' '+arg+' '+host_ip+' '+output,shell=True)
            murmur(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script murmur-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            murmur(host_ip,desc)
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