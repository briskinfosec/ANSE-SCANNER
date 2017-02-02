def distcc(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for distributed compiler daemon distcc:
      [1] distcc-cve2004-2687
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File distcc-cve2004-2687

Script types: portrule
Categories: exploit, intrusive, vuln
Download: http://nmap.org/svn/scripts/distcc-cve2004-2687.nse

User Summary
Detects and exploits a remote code execution vulnerability in the distributed compiler daemon distcc. The vulnerability
was disclosed in 2002, but is still present in modern implementation due to poor configuration of the service.

Script Arguments
cmd
the command to run at the remote server
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -p 3632 <ip> --script distcc-exec --script-args="distcc-exec.cmd='id'"

Default Option Used in script:
nmap  --script [script name] -p 3632 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2628[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3632"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script distcc-cve2004-2687  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            distcc(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script distcc-cve2004-2687 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            distcc(host_ip,desc)      
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