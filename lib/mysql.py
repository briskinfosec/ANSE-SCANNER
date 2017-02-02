def mysql(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for  MySQL database server:
      [1] mysql-audit
      [2] mysql-brute
      [3] mysql-databases
      [4] mysql-dump-hashes
      [5] mysql-empty-password
      [6] mysql-dump-hashes
      [7] mysql-info
      [8] mysql-query
      [9] mysql-users
     [10] mysql-variables
     [11] mysql-vuln-cve2012-2122
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-audit

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/mysql-audit.nse

User Summary
Audits MySQL database server security configuration against parts of the CIS MySQL v1.0.2 benchmark (the engine
 can be used for other MySQL audits by creating appropriate audit files).

Script Arguments
mysql-audit.password
the password with which to connect to the database
mysql-audit.username
the username with which to connect to the database
mysql-audit.filename
the name of the file containing the audit rulebase

Example Usage
nmap -p 3306 --script mysql-audit --script-args "mysql-audit.username='root', \
  mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit'"

Default Option Used in script:
nmap  -p 3306 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3306[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3306"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mysql-audit -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mysql-audit -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/mysql-brute.nse

User Summary
Performs password guessing against MySQL.

Script Arguments
mysql-brute.timeout
socket timeout for connecting to MySQL (default 5s)
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap --script=mysql-brute <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script mysql-brute '+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script mysql-brute  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-databases

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/mysql-databases.nse

User Summary
Attempts to list all databases on a MySQL server.

Script Arguments
mysqluser
The username to use for authentication. If unset it attempts to use credentials found by mysql-databases or mysql-empty-password.
mysqlpass
The password to use for authentication. If unset it attempts to use credentials found by mysql-databases or mysql-empty-password.

Example Usage
nmap -sV --script=mysql-databases <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script mysql-databases '+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script mysql-databases  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-dump-hashes

Script types: portrule
Categories: auth, discovery, safe
Download: http://nmap.org/svn/scripts/mysql-dump-hashes.nse

User Summary
Dumps the password hashes from an MySQL server in a format suitable for cracking by tools such as John the Ripper.
Appropriate DB privileges (root) are required.
The username and password arguments take precedence over credentials discovered by the mysql-brute and mysql-empty-password scripts.

Script Arguments
username
the username to use to connect to the server
password
the password to use to connect to the server

Example Usage
nmap -p 3306 <ip> --script mysql-dump-hashes --script-args='username=root,password=secret'

Default Option Used in script:
nmap  -sV  -p 3306 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3306[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3306"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script mysql-dump-hashes -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mysql-dump-hashes -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-empty-password

Script types: portrule
Categories: intrusive, auth
Download: http://nmap.org/svn/scripts/mysql-empty-password.nse

User Summary
Checks for MySQL servers with an empty password for root or anonymous.

Example Usage
nmap -sV --script=mysql-empty-password <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script mysql-empty-password '+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script mysql-empty-password  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-enum

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/mysql-enum.nse

User Summary
Performs valid-user enumeration against MySQL server using a bug discovered and published by Kingcope (http://seclists.org/fulldisclosure/2012/Dec/9).
Server version 5.x are susceptible to an user enumeration attack due to different messages during login when using old authentication mechanism from versions 4.x and earlier.

Script Arguments
mysql-enum.timeout
socket timeout for connecting to MySQL (default 5s)
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.
brute.credfile, brute.delay, brute.emptypass, brute.firstonly, brute.guesses, brute.mode, brute.passonly, brute.retries, brute.threads, brute.unique, brute.useraspass
See the documentation for the brute library.

Example Usage
nmap --script=mysql-enum <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script mysql-enum'+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script mysql-enum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-info

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/mysql-info.nse

User Summary
Connects to a MySQL server and prints information such as the protocol and version numbers, thread ID, status, capabilities, and the password salt.
If service detection is performed and the server appears to be blocking our host or is blocked because of too many connections, then this script isn't run (see the portrule).

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
            subprocess.call('nmap  -sV --script mysql-info'+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script mysql-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-query

Script types: portrule
Categories: auth, discovery, safe
Download: http://nmap.org/svn/scripts/mysql-query.nse

User Summary
Runs a query against a MySQL database and returns the results as a table.

Script Arguments
mysql-query.noheaders
do not display column headers (default: false)
mysql-query.query
the query for which to return the results
mysql-query.username
(optional) the username used to authenticate to the database server
mysql-query.password
(optional) the password used to authenticate to the database server

Example Usage
nmap -p 3306 <ip> --script mysql-query --script-args='query="<query>"[,username=<username>,password=<password>]'ecret'

Default Option Used in script:
nmap  -sV  -p 3306 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3306[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3306"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script mysql-dump-hashes -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mysql-dump-hashes -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-users

Script types: portrule
Categories: auth, intrusive
Download: http://nmap.org/svn/scripts/mysql-users.nse

User Summary
Attempts to list all users on a MySQL server.

Script Arguments
mysqluser
The username to use for authentication. If unset it attempts to use credentials found by mysql-brute or mysql-empty-password.
mysqlpass
The password to use for authentication. If unset it attempts to use credentials found by mysql-brute or mysql-empty-password.

Example Usage
nmap -sV --script=mysql-users <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script mysql-users'+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script mysql-users -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "10":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-variables

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/mysql-variables.nse

User Summary
Attempts to show all variables on a MySQL server.

Script Arguments
mysqluser
The username to use for authentication. If unset it attempts to use credentials found by mysql-brute or mysql-empty-password.
mysqlpass
The password to use for authentication. If unset it attempts to use credentials found by mysql-brute or mysql-empty-password.

Example Usage
nmap -sV --script=mysql-variables <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script mysql-variables'+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script mysql-variables -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "11":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mysql-vuln-cve2012-2122

Script types: portrule
Categories: discovery, intrusive, vuln
Download: http://nmap.org/svn/scripts/mysql-vuln-cve2012-2122.nse

User Summary
Attempts to bypass authentication in MySQL and MariaDB servers by exploiting CVE2012-2122. If its vulnerable, it will also attempt to
dump the MySQL usernames and password hashes.
All MariaDB and MySQL versions up to 5.1.61, 5.2.11, 5.3.5, 5.5.22 are vulnerable but exploitation depends on whether memcmp() returns
an arbitrary integer outside of -128..127 range.
"When a user connects to MariaDB/MySQL, a token (SHA over a password and a random scramble string) is calculated and compared with the
expected value. Because of incorrect casting, it might've happened that the token and the expected value were considered equal, even if
the memcmp() returned a non-zero value. In this case MySQL/MariaDB would think that the password is correct, even while it is not.
Because the protocol uses random strings, the probability of hitting this bug is about 1/256. Which means, if one knows a user name to
connect (and "root" almost always exists), she can connect using *any* password by repeating connection attempts. ~300 attempts takes only
a fraction of second, so basically account password protection is as good as nonexistent."

Original public advisory:
    http://seclists.org/oss-sec/2012/q2/493

Interesting post about this vuln:
    https://community.rapid7.com/community/metasploit/blog/2012/06/11/cve-2012-2122-a-tragically-comedic-security-flaw-in-mysql

Script Arguments
mysql-vuln-cve2012-2122.pass
MySQL password. Default: nmapFTW.
mysql-vuln-cve2012-2122.user
MySQL username. Default: root.
mysql-vuln-cve2012-2122.iterations
Connection retries. Default: 1500.
mysql-vuln-cve2012-2122.socket_timeout
Socket timeout. Default: 5s.
vulns.showall
See the documentation for the vulns library.

Example Usage
    nmap -p3306 --script mysql-vuln-cve2012-2122 <target>
    nmap -sV --script mysql-vuln-cve2012-2122 <target>


Default Option Used in script:
nmap  -sV  -p 3306 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-3306[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="3306"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script mysql-vuln-cve2012-2122 -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mysql-vuln-cve2012-2122 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mysql(host_ip,desc)
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
    