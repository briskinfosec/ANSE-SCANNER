def qconn(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for QCONN daemon :
    \t[1] qconn-exec\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File qconn-exec

Script types: portrule
Categories: intrusive, exploit, vuln
Download: http://nmap.org/svn/scripts/qconn-exec.nse

User Summary
Attempts to identify whether a listening QNX QCONN daemon allows unauthenticated users to execute arbitrary operating system commands.
QNX is a commercial Unix-like real-time operating system, aimed primarily at the embedded systems market. The QCONN daemon is a
service provider that provides support, such as profiling system information, to remote IDE components. The QCONN daemon runs on
 port 8000 by default.

Script Arguments
qconn-exec.cmd
Set the operating system command to execute. The default value is "uname -a".
qconn-exec.timeout
Set the timeout in seconds. The default value is 30.
qconn-exec.bytes
Set the number of bytes to retrieve. The default value is 1024.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script qconn-exec --script-args qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd="uname -a" -p <port> <target>

Default Option Used in script:
nmap -sV -p 8000 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-8000[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="8000"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script qconn-exec -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            qconn(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script qconn-exec -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            qconn(host_ip,desc)
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