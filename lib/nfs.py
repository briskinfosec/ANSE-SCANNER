def nfs(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for remote NFS exports:
    \t[1] nfs-ls[2] nfs-showmount\n\t[3] nfs-statfs\n\t[0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File nfs-ls

Script types:
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/nfs-ls.nse

User Summary
Attempts to get useful information about files from NFS exports. The output is intended to resemble the output of ls.
The script starts by enumerating and mounting the remote NFS exports. After that it performs an NFS GETATTR procedure call for each mounted point in order to get its ACLs. For each mounted directory the script will try to list its file entries with their attributes.
Since the file attributes shown in the results are the result of GETATTR, READDIRPLUS, and similar procedures, the attributes are the attributes of the local filesystem.
These access permissions are shown only with NFSv3:
    Read: Read data from file or read a directory.
    Lookup: Look up a name in a directory (no meaning for non-directory objects).
    Modify: Rewrite existing file data or modify existing directory entries.
    Extend: Write new data or add directory entries.
    Delete: Delete an existing directory entry.
    Execute: Execute file (no meaning for a directory).

Recursive listing is not implemented.

Script Arguments
nfs-ls.time
Specifies which one of the last mac times to use in the files attributes output. Possible values are:

    m: last modification time (mtime)
    a: last access time (atime)
    c: last change time (ctime)

The default value is m (mtime).
nfs.version
The NFS protocol version to use
mount.version, rpc.protocol
See the documentation for the rpc library.
ls.checksum, ls.empty, ls.errors, ls.human, ls.maxdepth, ls.maxfiles
See the documentation for the ls library.

Example Usage
    nmap -p 111 --script=nfs-ls <target>
    nmap -sV --script=nfs-ls <target>

Default Option Used in script:
nmap -sV -p 111 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-111[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="111"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script nfs-ls -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nfs(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script nfs-ls -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nfs(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File nfs-showmount

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/nfs-showmount.nse

User Summary
Shows NFS exports, like the showmount -e command.

Script Arguments
mount.version, nfs.version, rpc.protocol
See the documentation for the rpc library.

Example Usage
nmap -sV --script=nfs-showmount <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script nfs-showmount'+' '+arg+' '+host_ip+' '+output,shell=True)
            nfs(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script nfs-showmount -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nfs(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File nfs-statfs

Script types:
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/nfs-statfs.nse

User Summary
Retrieves disk space statistics and information from a remote NFS share. The output is intended to resemble the output of df.
The script will provide pathconf information of the remote NFS if the version used is NFSv3.

Script Arguments
nfs-statfs.human
If set to 1 or true, shows file sizes in a human readable format with suffixes like KB and MB.
mount.version, nfs.version, rpc.protocol
See the documentation for the rpc library.

Example Usage
nmap -p 111 --script=nfs-statfs <target>
nmap -sV --script=nfs-statfs <target>

Default Option Used in script:
nmap -sV -p 111 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-111[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="111"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script nfs-statfs -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nfs(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script nfs-statfs -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            nfs(host_ip,desc)
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
    