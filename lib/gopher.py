def gopher(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for gopher service:
     [1] gopher-ls
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File gopher-ls

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/gopher-ls.nse

User Summary
Lists files and directories at the root of a gopher service.

Script Arguments
gopher-ls.maxfiles
If set, limits the amount of files returned by the script. If set to 0 or less, all files are shown.
The default value is 10.

Example Usage
nmap -p 70 --script gopher-ls --script-args gopher-ls.maxfiles=100 <target>
Default Option Used in script:
nmap  -p 19150 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-19150[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="19150"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script gopher-ls -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            gopher(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script gopher-ls -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            gopher(host_ip,desc) 
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

        