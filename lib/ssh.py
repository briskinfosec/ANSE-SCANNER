def ssh(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for SSH server:
    \t[1] ssh-hostkey\n\t[2] ssh2-enum-algos[3] sshv1\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssh-hostkey

Script types:
Categories: safe, default, discovery
Download: http://nmap.org/svn/scripts/ssh-hostkey.nse

User Summary
Shows SSH hostkeys.
Shows the target SSH server's key fingerprint and (with high enough verbosity level) the public key itself.
It records the discovered host keys in nmap.registry for use by other scripts. Output can be controlled with
the ssh_hostkey script argument.
You may also compare the retrieved key with the keys in your known-hosts file using the known-hosts argument.
The script also includes a postrule that check for duplicate hosts using the gathered keys.

Script Arguments
ssh-hostkey.known-hosts
If this is set, the script will check if the known hosts file contains a key for the host being scanned and will
compare it with the keys that have been found by the script. The script will try to detect your known-hosts file
but you can, optionally, pass the path of the file to this option.
ssh-hostkey.known-hosts-path.
Path to a known_hosts file.
ssh_hostkey
Controls the output format of keys. Multiple values may be given, separated by spaces. Possible values are
    "full": The entire key, not just the fingerprint.
    "bubble": Bubble Babble output,
    "visual": Visual ASCII art representation.
    "all": All of the above.

Example Usage
nmap host --script ssh-hostkey --script-args ssh_hostkey=full
nmap host --script ssh-hostkey --script-args ssh_hostkey=all
nmap host --script ssh-hostkey --script-args ssh_hostkey='visual bubble'


Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ssh-hostkey'+' '+arg+' '+host_ip+' '+output,shell=True)
            ssh(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ssh-hostkey -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssh(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssh2-enum-algos

Script types: portrule
Categories: safe, discovery
Download: http://nmap.org/svn/scripts/ssh2-enum-algos.nse

User Summary
Reports the number of algorithms (for encryption, compression, etc.) that the target SSH2 server
offers. If verbosity is set, the offered algorithms are each listed by type.
If the "client to server" and "server to client" algorithm lists are identical (order specifies preference)
then the list is shown only once under a combined type.

Example Usage
nmap --script ssh2-enum-algos target


Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ssh2-enum-algos'+' '+arg+' '+host_ip+' '+output,shell=True)
            ssh(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ssh2-enum-algos -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssh(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File sshv1

Script types: portrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/sshv1.nse

User Summary
Checks if an SSH server supports the obsolete and less secure SSH Protocol Version 1.

Example Usage
nmap -sV -sC <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script sshv1'+' '+arg+' '+host_ip+' '+output,shell=True)
            ssh(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script sshv1 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssh(host_ip,desc)
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