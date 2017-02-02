def jdwp(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script forjava's remote debugging port:
     [1] jdwp-exec
     [2] jdwp-info
     [3] jdwp-inject
     [4] jdwp-version
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File jdwp-exec

Script types: portrule
Categories: exploit, intrusive
Download: http://nmap.org/svn/scripts/jdwp-exec.nse

User Summary
Attempts to exploit java's remote debugging port. When remote debugging port is left open, it is possible to inject java bytecode and achieve remote code execution. This script abuses this to inject and execute a Java class file that executes the supplied shell command and returns its output.
The script injects the JDWPSystemInfo class from nselib/jdwp-class/ and executes its run() method which accepts a shell command as its argument.

Script Arguments
jdwp-exec.cmd
Command to execute on the remote system.

Example Usage
nmap -sT <target> -p <port> --script=+jdwp-exec --script-args cmd="date"

Default Option Used in script:
nmap  -sT -p 2010  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2010[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2010"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sT --script jdwp-exec -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            jdwp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sT --script jdwp-exec -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            jdwp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File jdwp-info

Script types: portrule
Categories: default, safe, discovery
Download: http://nmap.org/svn/scripts/jdwp-info.nse

User Summary
Attempts to exploit java's remote debugging port. When remote debugging port is left open, it is possible to inject java bytecode and achieve remote code execution. This script injects and execute a Java class file that returns remote system information.

Example Usage
nmap -sT <target> -p <port> --script=+jdwp-info

Default Option Used in script:
nmap  -sT -p 2010  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2010[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2010"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sT --script jdwp-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            jdwp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sT --script jdwp-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            jdwp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File jdwp-inject

Script types: portrule
Categories: exploit, intrusive
Download: http://nmap.org/svn/scripts/jdwp-inject.nse

User Summary
Attempts to exploit java's remote debugging port. When remote debugging port is left open, it is possible to inject java bytecode and achieve remote code execution. This script allows injection of arbitrary class files.
After injection, class' run() method is executed. Method run() has no parameters, and is expected to return a string.
You must specify your own .class file to inject by filename argument. See nselib/data/jdwp-class/README for more.

Script Arguments
jdwp-inject.filename
Java .class file to inject.

Example Usage
nmap -sT <target> -p <port> --script=+jdwp-inject --script-args filename=HelloWorld.class

Default Option Used in script:
nmap  -sT -p 2010  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2010[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2010"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sT --script jdwp-inject -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            jdwp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sT --script jdwp-inject -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            jdwp(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File jdwp-version

Script types: portrule
Categories: version
Download: http://nmap.org/svn/scripts/jdwp-version.nse

User Summary
Detects the Java Debug Wire Protocol. This protocol is used by Java programs to be debugged via the network.
It should not be open to the public Internet, as it does not provide any security against malicious attackers who
can inject their own bytecode into the debugged process.
Documentation for JDWP is available at http://java.sun.com/javase/6/docs/technotes/guides/jpda/jdwp-spec.html

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
            subprocess.call('nmap -sV  --script jdwp-version'+' '+arg+' '+host_ip+' '+output,shell=True)
            jdwp(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script jdwp-version -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            jdwp(host_ip,desc)
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
            