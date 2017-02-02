def bitcoin(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for bitcoin server
     [1] bitcoin-getaddr
     [2] bitcoin-info
     [3] bitcoinrpc-info
     [4] bittorrent-discovery
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File bitcoin-getaddr

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/bitcoin-getaddr.nse

User Summary
Queries a Bitcoin server for a list of known Bitcoin nodes

Script Arguments
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap -p 8333 --script bitcoin-getaddr <ip>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-8333 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8333"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script bitcoin-getaddr -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            bitcoin(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script bitcoin-getaddr -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            bitcoin(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File bitcoin-info

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/bitcoin-info.nse

User Summary
Extracts version and node information from a Bitcoin server

Example Usage
nmap -p 8333 --script bitcoin-info <ip>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-8333 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8333"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script auth-spoof -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            bitcoin(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script auth-spoof -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            bitcoin(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File bitcoinrpc-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/bitcoinrpc-info.nse

User Summary
Obtains information from a Bitcoin server by calling getinfo on its JSON-RPC interface.

Script Arguments
creds.global
http credentials used for the query (user:pass)
slaxml.debug
See the documentation for the slaxml library.
creds.[service]
See the documentation for the creds library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 8332 --script bitcoinrpc-info --script-args creds.global=<user>:<pass> <target>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-8332[Y/N]:")
        default_port="8332"
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            default_port="8333"
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script bitcoinrpc-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            bitcoin(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script bitcoinrpc-info -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            bitcoin(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File bittorrent-discovery

Script types: prerule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/bittorrent-discovery.nse

User Summary
Discovers bittorrent peers sharing a file based on a user-supplied torrent file or magnet link.
Peers implement the Bittorrent protocol and share the torrent, whereas the nodes (only shown
if the include-nodes NSE argument is given) implement the DHT protocol and are used to track the peers.
The sets of peers and nodes are not the same, but they usually intersect.
If the newtargets script-arg is supplied it adds the discovered peers as targets.

Script Arguments
bittorrent-discover.timeout
desired (not actual) timeout for the DHT discovery (default = 30s)
bittorrent-discover.include-nodes
boolean selecting whether to show only nodes
bittorrent-discovery.magnet
a string containing the magnet link of the torrent
bittorrent-discovery.torrent
a string containing the filename of the torrent file
max-newtargets, newtargets
See the documentation for the target library.
http.max-cache-size, http.max-pipeline, http.pipeline, http.useragent
See the documentation for the http library.
slaxml.debug
See the documentation for the slaxml library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script bittorrent-discovery --script-args newtargets,bittorrent-discovery.torrent=<torrent_file>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-NO port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script bittorrent-discovery '+arg+' '+host_ip+' '+output,shell=True)
            bitcoin(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script bitcoinrpc-info -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            bitcoin(host_ip,desc)      
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