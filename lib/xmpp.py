def xmpp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for XMPP server:
    \t[1] xmpp-info\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File xmpp-info

Script types: portrule
Categories: default, safe, discovery, version
Download: http://nmap.org/svn/scripts/xmpp-info.nse

User Summary
Connects to XMPP server (port 5222) and collects server information such as: supported auth mechanisms, compression methods, whether TLS is supported and mandatory, stream management, language, support of In-Band registration, server capabilities. If possible, studies server vendor.

Script Arguments
xmpp-info.alt_server_name
If set, overwrites alternative hello name sent to the server. This name should differ from the real DNS name. It is used to find out whether the server refuses to talk if a wrong name is used. Default is ".".
xmpp-info.no_starttls
If set, disables TLS processing.
xmpp-info.server_name
If set, overwrites hello name sent to the server. It can be necessary if XMPP server's name differs from DNS name.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

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
            subprocess.call('nmap -sV  --script xmpp-info '+' '+arg+' '+host_ip+' '+output,shell=True)
            xmpp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script xmpp-info  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            xmpp(host_ip,desc)
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