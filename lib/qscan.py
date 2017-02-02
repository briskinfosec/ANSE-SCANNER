def qscan(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Qscan:
    \t[1] qscan\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File qscan

Script types: hostrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/qscan.nse

User Summary
Repeatedly probe open and/or closed ports on a host to obtain a series of round-trip time values for each port.
These values are used to group collections of ports which are statistically different from other groups. Ports being
in different groups (or "families") may be due to network mechanisms such as port forwarding to machines behind a NAT.
In order to group these ports into different families, some statistical values must be computed. Among these values are
the mean and standard deviation of the round-trip times for each port. Once all of the times have been recorded and these
values have been computed, the Student's t-test is used to test the statistical significance of the differences between
each port's data. Ports which have round-trip times that are statistically the same are grouped together in the same family.
This script is based on Doug Hoyte's Qscan documentation and patches for Nmap.

Script Arguments
numclosed
Maximum number of closed ports to probe (default 1). A negative number disables the limit.
numopen
Maximum number of open ports to probe (default 8). A negative number disables the limit.
confidence
Confidence level: 0.75, 0.9, 0.95, 0.975, 0.99, 0.995, or 0.9995.
numtrips
Number of round-trip times to try to get.
delay
Average delay between packet sends. This is a number followed by ms for milliseconds or s for seconds. (m and h are also supported but are too long for timeouts.) The actual delay will randomly vary between 50% and 150% of the time specified. Default: 200ms.

Example Usage
nmap --script qscan --script-args qscan.confidence=0.95,qscan.delay=200ms,qscan.numtrips=10 target

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script qscan'+' '+arg+' '+host_ip+' '+output,shell=True)
            qscan(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script qscan -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            qscan(host_ip,desc)
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