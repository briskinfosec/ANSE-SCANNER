def mssql(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for Microsoft SQL Server (ms-sql):
     [1] ms-sql-brute
     [2] ms-sql-config
     [3] ms-sql-dac
     [4] ms-sql-dump-hashes
     [5] ms-sql-hasdbaccess
     [6] ms-sql-hasdbaccess
     [7] ms-sql-info
     [8] ms-sql-ntlm-info
     [9] ms-sql-query ms-sql-tables
    [10] ms-sql-tables
    [11] ms-sql-xp-cmdshell
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-brute

Script types: hostrule, portrule
Categories: brute, intrusive
Download: http://nmap.org/svn/scripts/ms-sql-brute.nse

User Summary
Performs password guessing against Microsoft SQL Server (ms-sql).
Works best in conjunction with the broadcast-ms-sql-discover script.
SQL Server credentials required: No (will not benefit from mssql.username & mssql.password).

Script Arguments
ms-sql-brute.ignore-lockout
WARNING! Including this argument will cause the script to continue attempting to brute-forcing passwords for users even after a user has
been locked out. This may result in many SQL Server logins being locked out!
ms-sql-brute.brute-windows-accounts
Enable targeting Windows accounts as part of the brute force attack. This should be used in conjunction with the mssql library's mssql.
domain argument.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only,
mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
    nmap -p 445 --script ms-sql-brute --script-args mssql.instance-all,userdb=customuser.txt,passdb=custompass.txt <host>
    nmap -p 1433 --script ms-sql-brute --script-args userdb=customuser.txt,passdb=custompass.txt <host>

Default Option Used in script:
nmap  -p  445,1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445,1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445,1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-config

Script types: hostrule, portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ms-sql-config.nse

User Summary
Queries Microsoft SQL Server (ms-sql) instances for a list of databases, linked servers, and configuration settings.

Script Arguments
ms-sql-config.showall
If set, shows all configuration options.
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 1433 --script ms-sql-config --script-args mssql.username=sa,mssql.password=sa <host>

Default Option Used in script:
nmap  -p  1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-config -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-config -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-dac

Script types: hostrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ms-sql-dac.nse

User Summary
Queries the Microsoft SQL Browser service for the DAC (Dedicated Admin Connection) port of a given (or all) SQL Server instance.
The DAC port is used to connect to the database instance when normal connection attempts fail, for example, when server is hanging,
out of memory or in other bad states. In addition, the DAC port provides an admin with access to system objects otherwise not accessible
over normal connections.

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only,
mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
sudo nmap -sU -p 1434 --script ms-sql-dac <ip>

Default Option Used in script:
nmap  -sU  -p  1434  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1434[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1434"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sU --script ms-sql-dac -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU  --script ms-sql-dac -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-dump-hashes

Script types: hostrule, portrule
Categories: auth, discovery, safe
Download: http://nmap.org/svn/scripts/ms-sql-dump-hashes.nse

User Summary
Dumps the password hashes from an MS-SQL server in a format suitable for cracking by tools such as John-the-ripper.
In order to do so the user needs to have the appropriate DB privileges.
Credentials passed as script arguments take precedence over credentials discovered by other scripts.

Script Arguments
ms-sql-dump-hashes.dir
Dump hashes to a file in this directory. File name is <ip>_<instance>_ms-sql_hashes.txt. Default: no file is saved.
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 1433 <ip> --script ms-sql-dump-hashes

Default Option Used in script:
nmap  -p  1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-dump-hashes -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-dump-hashes -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-hasdbaccess

Script types: hostrule, portrule
Categories: auth, intrusive
Download: http://nmap.org/svn/scripts/ms-sql-hasdbaccess.nse

User Summary
Attempts to authenticate to Microsoft SQL Servers using an empty password for the sysadmin (sa) account.
SQL Server credentials required: No (will not benefit from mssql.username & mssql.password). Run criteria:

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 445 --script ms-sql-hasdbaccess --script-args mssql.instance-all <host>
nmap -p 1433 --script ms-sql-hasdbaccess <host>

Default Option Used in script:
nmap  -p  445,1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445,1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445,1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-hasdbaccess -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-hasdbaccess -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-hasdbaccess

Script types: hostrule, portrule
Categories: auth, discovery, safe
Download: http://nmap.org/svn/scripts/ms-sql-hasdbaccess.nse

User Summary
Queries Microsoft SQL Server (ms-sql) instances for a list of databases a user has access to.
SQL Server credentials required: Yes (use ms-sql-brute, ms-sql-hasdbaccess and/or mssql.username & mssql.password) Run criteria:
    Host script: Will run if the mssql.instance-all, mssql.instance-name
or mssql.instance-port script arguments are used (see mssql.lua).
    Port script: Will run against any services identified as SQL Servers, but only
if the mssql.instance-all, mssql.instance-name and mssql.instance-port script arguments are NOT used.
The script needs an account with the sysadmin server role to work.
When run, the script iterates over the credentials and attempts to run the command for each available set of credentials.
NOTE: The "owner" field in the results will be truncated at 20 characters. This is a limitation of the sp_MShasdbaccess stored procedure
that the script uses.
NOTE: Communication with instances via named pipes depends on the smb library. To communicate with (and possibly to discover) instances
via named pipes, the host must have at least one SMB port (e.g. TCP 445) that was scanned and found to be open. Additionally, named pipe
connections may require Windows authentication to connect to the Windows host (via SMB) in addition to the authentication required to
connect to the SQL Server instances itself. See the documentation and arguments for the smb library for more information.
NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate with ports that were not included in the port list for
the Nmap scan. This can be disabled using the mssql.scanned-ports-only script argument.

Script Arguments
ms-sql-hasdbaccess.limit
limits the amount of databases per-user that are returned (default 5). If set to zero or less all databases the user has access to are returned.
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 1433 --script ms-sql-hasdbaccess --script-args mssql.username=sa,mssql.password=sa <host>

Default Option Used in script:
nmap  -p 1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-hasdbaccess -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-hasdbaccess -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-info

Script types: hostrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/ms-sql-info.nse

User Summary
Attempts to determine configuration and version information for Microsoft SQL Server instances.

SQL Server credentials required: No (will not benefit from mssql.username & mssql.password). Run criteria:
    Host script: Will always run.
    Port script: N/A
NOTE: Unlike previous versions, this script will NOT attempt to log in to SQL Server instances. Blank passwords can be checked using the
ms-sql-info script. E.g.: nmap -sn --script ms-sql-info --script-args mssql.instance-all <host>

The script uses two means of getting version information for SQL Server instances:
    Querying the SQL Server Browser service, which runs by default on UDP port
1434 on servers that have SQL Server 2000 or later installed. However, this service may be disabled without affecting the functionality of
the instances. Additionally, it provides imprecise version information.
    Sending a probe to the instance, causing the instance to respond with
information including the exact version number. This is the same method that Nmap uses for service versioning; however, this script can also
do the same for instances accessible via Windows named pipes, and can target all of the instances listed by the SQL Server Browser service.
In the event that the script can connect to the SQL Server Browser service (UDP 1434) but is unable to connect directly to the instance to
obtain more accurate version information (because ports are blocked or the mssql.scanned-ports-only argument has been used), the script will
rely only upon the version number provided by the SQL Server Browser/Monitor, which has the following limitations:
    For SQL Server 2000 and SQL Server 7.0 instances, the RTM version number is
always given, regardless of any service packs or patches installed.
    For SQL Server 2005 and later, the version number will reflect the service pack installed, but the script will not be able
to tell whether patches have been installed.
Where possible, the script will determine major version numbers, service pack levels and whether patches have been installed.
However, in cases where particular determinations can not be made, the script will report only what can be confirmed.

NOTE: Communication with instances via named pipes depends on the smb library. To communicate with (and possibly to discover) instances
via named pipes, the host must have at least one SMB port (e.g. TCP 445) that was scanned and found to be open. Additionally, named pipe
connections may require Windows authentication to connect to the Windows host (via SMB) in addition to the authentication required to connect
to the SQL Server instances itself. See the documentation and arguments for the smb library for more information.
NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate with ports that were not included in the port
list for the Nmap scan. This can be disabled using the mssql.scanned-ports-only script argument.

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only,
mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 445 --script ms-sql-info <host>
nmap -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 <host>

Default Option Used in script:
nmap  -p 445,1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445,1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445,1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-ntlm-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/ms-sql-ntlm-info.nse

User Summary
This script enumerates information from remote Microsoft SQL services with NTLM authentication enabled.
Sending a MS-TDS NTLM authentication request with an invalid domain and null credentials will cause the remote service to respond with a NTLMSSP message disclosing information to include NetBIOS, DNS, and OS build version.

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 1433 --script ms-sql-ntlm-info <target>

Default Option Used in script:
nmap  -p 1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-ntlm-info -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-ntlm-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-query

Script types: hostrule, portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ms-sql-query.nse

User Summary
Runs a query against Microsoft SQL Server (ms-sql).
SQL Server credentials required: Yes (use ms-sql-brute, ms-sql-empty-password and/or mssql.username & mssql.password) Run criteria:
    Host script: Will run if the mssql.instance-all, mssql.instance-name
or mssql.instance-port script arguments are used (see mssql.lua).
    Port script: Will run against any services identified as SQL Servers, but only
if the mssql.instance-all, mssql.instance-name and mssql.instance-port script arguments are NOT used.
NOTE: Communication with instances via named pipes depends on the smb library. To communicate with (and possibly to discover) instances
via named pipes, the host must have at least one SMB port (e.g. TCP 445) that was scanned and found to be open. Additionally, named pipe 
onnections may require Windows authentication to connect to the Windows host (via SMB) in addition to the authentication required to connect
to the SQL Server instances itself. See the documentation and arguments for the smb library for more information.
NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate with ports that were not included in the port list for the
Nmap scan. This can be disabled using the mssql.scanned-ports-only script argument.

Script Arguments
mssql.database
Database to connect to (default: tempdb)
ms-sql-query.query
The query to run against the server. (default: SELECT @@version version)
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only,
mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 1433 --script ms-sql-query --script-args mssql.username=sa,mssql.password=sa,ms-sql-query.query="SELECT * FROM master..syslogins" <host>

Default Option Used in script:
nmap  -p 1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-query -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-query -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "10":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-tables

Script types: hostrule, portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ms-sql-tables.nse

User Summary
Queries Microsoft SQL Server (ms-sql) for a list of tables per database.
SQL Server credentials required: Yes (use ms-sql-brute, ms-sql-empty-password and/or mssql.username & mssql.password) Run criteria:
    Host script: Will run if the mssql.instance-all, mssql.instance-name
or mssql.instance-port script arguments are used (see mssql.lua).
    Port script: Will run against any services identified as SQL Servers, but only
if the mssql.instance-all, mssql.instance-name and mssql.instance-port script arguments are NOT used.
The sysdatabase table should be accessible by more or less everyone.
Once we have a list of databases we iterate over it and attempt to extract table names. In order for this to succeed we need to
have either sysadmin privileges or an account with access to the db. So, each database we successfully enumerate tables from we mark as finished, then iterate over known user accounts until either we have exhausted the users or found all tables in all the databases.
System databases are excluded.

NOTE: Communication with instances via named pipes depends on the smb library. To communicate with (and possibly to discover) instances
via named pipes, the host must have at least one SMB port (e.g. TCP 445) that was scanned and found to be open. Additionally, named pipe
connections may require Windows authentication to connect to the Windows host (via SMB) in addition to the authentication required to connect
to the SQL Server instances itself. See the documentation and arguments for the smb library for more information.
NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate with ports that were not included in the port list for
the Nmap scan. This can be disabled using the mssql.scanned-ports-only script argument.

Script Arguments
ms-sql-tables.keywords
If set shows only tables or columns matching the keywords
ms-sql-tables.maxdb
Limits the amount of databases that are processed and returned (default 5). If set to zero or less all databases are processed.
ms-sql-tables.maxtables
Limits the amount of tables returned (default 5). If set to zero or less all tables are returned.
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only,
mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 1433 --script ms-sql-tables --script-args mssql.username=sa,mssql.password=sa <host>

Default Option Used in script:
nmap  -p 1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-tables -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-tables -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "11":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ms-sql-xp-cmdshell

Script types: hostrule, portrule
Categories: intrusive
Download: http://nmap.org/svn/scripts/ms-sql-xp-cmdshell.nse

User Summary
Attempts to run a command using the command shell of Microsoft SQL Server (ms-sql).
SQL Server credentials required: Yes (use ms-sql-brute, ms-sql-empty-password and/or mssql.username & mssql.password) Run criteria:
    Host script: Will run if the mssql.instance-all, mssql.instance-name
or mssql.instance-port script arguments are used (see mssql.lua).
    Port script: Will run against any services identified as SQL Servers, but only

if the mssql.instance-all, mssql.instance-name and mssql.instance-port script arguments are NOT used.
The script needs an account with the sysadmin server role to work.
When run, the script iterates over the credentials and attempts to run the command until either all credentials are exhausted or
until the command is executed.
NOTE: Communication with instances via named pipes depends on the smb library. To communicate with (and possibly to discover) instances
via named pipes, the host must have at least one SMB port (e.g. TCP 445) that was scanned and found to be open. Additionally, named pipe
connections may require Windows authentication to connect to the Windows host (via SMB) in addition to the authentication required to
connect to the SQL Server instances itself. See the documentation and arguments for the smb library for more information.
NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate with ports that were not included in the port list
for the Nmap scan. This can be disabled using the mssql.scanned-ports-only script argument.

Script Arguments
ms-sql-xp-cmdshell.cmd
The OS command to run (default: ipconfig /all).
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only,
mssql.timeout, mssql.username
See the documentation for the mssql library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage

nmap -p 445 --script ms-sql-discover,ms-sql-empty-password,ms-sql-xp-cmdshell <host>
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd="net user test test /add" <host>

Default Option Used in script:
nmap  -p 445,1433  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445,1433[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445,1433"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-xp-cmdshell -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script ms-sql-xp-cmdshell -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mssql(host_ip,desc)
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