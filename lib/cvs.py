def cvs(host_ip,desc):
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
      [1] cvs-brute-repository
      [2] cvs-brute
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File cvs-brute-repository

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/cvs-brute-repository.nse
.
User Summary
Attempts to guess the name of the CVS repositories hosted on the remote server. With knowledge of the
 correct repository name, usernames and passwords can be guessed.

Script Arguments
cvs-brute-repository.repofile
a file containing a list of repositories to guess
cvs-brute-repository.nodefault
when set the script does not attempt to guess the list of hardcoded repositories
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly,
brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap -p 2401 --script cvs-brute-repository <host>

Default Option Used in script:
nmap --script [script name] -p 2401 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2401[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2401"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script cvs-brute-repository  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            cvs(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script cvs-brute-repository -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            cvs(host_ip,desc)      
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    if option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File cvs-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/cvs-brute.nse

User Summary
Performs brute force password auditing against CVS pserver authentication.

Script Arguments
cvs-brute.repo
string containing the name of the repository to brute if no repo was given the script checks the registry for
any repositories discovered by the cvs-brute-repository script. If the registry contains any discovered repositories,
the script attempts to brute force the credentials for the first one.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.
creds.[service], creds.global
See the documentation for the creds library.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.

Example Usage
nmap -p 2401 --script cvs-brute <host>

Default Option Used in script:
nmap --script [script name] -p 2401 [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-2401[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="2401"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script cvs-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            cvs(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script cvs-brute -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            cvs(host_ip,desc)      
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