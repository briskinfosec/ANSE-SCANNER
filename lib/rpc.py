def rpc(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for RPC:
    \t[1] rpc-grind\n\t[2] rpcinfo\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rpc-grind

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/rpc-grind.nse

User Summary
Fingerprints the target RPC port to extract the target service, RPC number and version.
The script works by sending RPC Null call requests with a random high version unsupported number to the target service with iterated over RPC program numbers from the nmap-rpc file and check for replies from the target port. A reply with a RPC accept state 2 (Remote can't support version) means that we the request sent the matching program number, and we proceed to extract the supported versions. A reply with an accept state RPC accept state 1 (remote hasn't exported program) means that we have sent the incorrect program number. Any other accept state is an incorrect behaviour.

Script Arguments
rpc-grind.threads
Number of grinding threads. Defaults to 4
mount.version, nfs.version, rpc.protocol
See the documentation for the rpc library.

Example Usage
nmap -sV <target>
nmap --script rpc-grind <target>
nmap --script rpc-grind --script-args 'rpc-grind.threads=8' -p <targetport>
<target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script rpc-grind'+' '+arg+' '+host_ip+' '+output,shell=True)
            rpc(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script rpc-grind -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rpc(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File rpcinfo

Script types: portrule
Categories: discovery, default, safe, version
Download: http://nmap.org/svn/scripts/rpcinfo.nse

User Summary
Connects to portmapper and fetches a list of all registered programs. It then prints out a table including (for each program) the RPC program number, supported version numbers, port number and protocol, and program name.

Script Arguments
mount.version, nfs.version, rpc.protocol
See the documentation for the rpc library.

Example Usage
nmap -sV <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script rpcinfo'+' '+arg+' '+host_ip+' '+output,shell=True)
            rpc(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script rpcinfo -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            rpc(host_ip,desc)
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