def coap(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for CoAP endpoints:
     [1] coap-resources
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File coap-resources

Script types: portrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/coap-resources.nse

User Summary
Dumps list of available resources from CoAP endpoints.
This script establishes a connection to a CoAP endpoint and performs a GET request on a resource.
The default resource for our request is <code>/.well-known/core</core>, which should contain a list of resources
provided by the endpoint.

Script Arguments
coap-resources.uri
URI to request via the GET method, /.well-known/core by default.

Example Usage
nmap -p U:5683 -sU --script coap-resources <target>

Default Option Used in script:
nmap  -sU  --script [script name] -p U:5683 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:5683[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:5683"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script coap-resources '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            coap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script coap-resources -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            coap(host_ip,desc)
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