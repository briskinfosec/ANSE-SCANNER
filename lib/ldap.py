def ldap(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for LDAP:
      [1] ldap-brute
      [2] ldap-novell-getpass
      [3] ldap-rootdse
      [4] ldap-search
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ldap-brute

Script types: portrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/ldap-brute.nse

User Summary
Attempts to brute-force LDAP authentication. By default it uses the built-in username and password lists. In order
to use your own lists use the userdb and passdb script arguments.
This script does not make any attempt to prevent account lockout! If the number of passwords in the dictionary exceed
the amount of allowed tries, accounts will be locked out. This usually happens very quickly.
Authenticating against Active Directory using LDAP does not use the Windows user name but the user accounts distinguished
name. LDAP on Windows 2003 allows authentication using a simple user name rather than using the fully distinguished name.

Script Arguments
ldap.upnsuffix
If set, the script will append this suffix value to the username to create a User Principle Name (UPN). For example if the ldap.upnsuffix
value were 'mycompany.com' and the username being tested was 'pete' then this script would attempt to login as 'pete@mycompany.com'.
This setting should only have value when running the script against a Microsoft Active Directory LDAP implementation. When the UPN is known
using this setting should provide more reliable results against domains that have been organized into various OUs or child domains.
If both ldap.base and ldap.upnsuffix are unset the user list must either contain the distinguished name of each user or the server must s
upport authentication using a simple user name. See the AD discussion in the description. DO NOT use ldap.upnsuffix in conjunction with ldap.
base as attempts to login will fail.
ldap.saveprefix
If set, the script will save the output to a file beginning with the specified path and name. The file suffix will automatically be added
based on the output type selected.
ldap.savetype
If set, the script will save the passwords in the specified format. The current formats are CSV, verbose and plain. In both verbose and
plain records are separated by colons. The difference between the two is that verbose includes the credential state. When ldap.savetype is
used without ldap.saveprefix then ldap-brute will be prefixed to all output filenames.
ldap.base
If set, the script will use it as a base for the password guessing attempts. If both ldap.base and ldap.upnsuffix are unset the user list
must either contain the distinguished name of each user or the server must support authentication using a simple user name. See the AD
discussion in the description. DO NOT use ldap.upnsuffix in conjunction with ldap.base as attempts to login will fail.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
creds.[service], creds.global
See the documentation for the creds library.

Example Usage
nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=cqure,dc=net"' <host>

Default Option Used in script:
nmap   -p 389  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-389[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="389"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ldap-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ldap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ldap-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ldap(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ldap-novell-getpass

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ldap-novell-getpass.nse

User Summary
Universal Password enables advanced password policies, including extended characters in passwords, synchronization of passwords
from eDirectory to other systems, and a single password for all access to eDirectory.
In case the password policy permits administrators to retrieve user passwords ("Allow admin to retrieve passwords" is set in the
password policy) this script can retrieve the password.

Script Arguments
ldap-novell-getpass.password
The LDAP password to use when connecting to the server
ldap-novell-getpass.account
The name of the account to retrieve the password for
ldap-novell-getpass.username
The LDAP username to use when connecting to the server

Example Usage
nmap -p 636 --script ldap-novell-getpass --script-args \
'ldap-novell-getpass.username="CN=admin,O=cqure", \
ldap-novell-getpass.password=pass1234, \
ldap-novell-getpass.account="CN=paka,OU=hr,O=cqure"

Default Option Used in script:
nmap   -p 389  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-389[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="389"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ldap-brute -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ldap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ldap-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ldap(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ldap-rootdse

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ldap-rootdse.nse

User Summary
Retrieves the LDAP root DSA-specific Entry (DSE)

Example Usage
nmap -p 389 --script ldap-rootdse <host>

Default Option Used in script:
nmap   -p 389  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-389[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="389"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ldap-rootdse -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ldap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ldap-rootdse -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ldap(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ldap-search

Script types: portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/ldap-search.nse

User Summary
Attempts to perform an LDAP search and returns all matches.
If no username and password is supplied to the script the Nmap registry is consulted. If the ldap-brute script has
been selected and it found a valid account, this account will be used. If not anonymous bind will be used as a last attempt.

Script Arguments
ldap.searchattrib
When used with the 'custom' qfilter, this parameter works in conjunction with ldap.searchvalue to allow the user to
specify a custom attribute and value as search criteria.
ldap.maxobjects
If set, overrides the number of objects returned by the script (default 20). The value -1 removes the limit completely.
ldap.qfilter
If set, specifies a quick filter. The library does not support parsing real LDAP filters. The following values are valid
for the filter parameter: computer, users, ad_dcs, custom or all. If no value is specified it defaults to all.
ldap.attrib
If set, the search will include only the attributes specified. For a single attribute a string value can be used, if multiple
attributes need to be supplied a table should be used instead.
ldap.searchvalue
When used with the 'custom' qfilter, this parameter works in conjunction with ldap.searchattrib to allow the user to specify a
custom attribute and value as search criteria. This parameter DOES PERMIT the use of the asterisk '*' as a wildcard.
ldap.password
If set, used together with the username to authenticate to the LDAP server
ldap.savesearch
If set, the script will save the output to a file beginning with the specified path and name. The file suffix of .CSV as well
as the hostname and port will automatically be added based on the output type selected.
ldap.username
If set, the script will attempt to perform an LDAP bind using the username and password
ldap.base
If set, the script will use it as a base for the search. By default the defaultNamingContext is retrieved and used. If no
defaultNamingContext is available the script iterates over the available namingContexts

Example Usage
   nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=ldaptest,cn=users,dc=cqure,dc=net",ldap.password=ldaptest,
ldap.qfilter=users,ldap.attrib=sAMAccountName' <host>
   nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=ldaptest,cn=users,dc=cqure,dc=net",ldap.password=ldaptest,
ldap.qfilter=custom,ldap.searchattrib="operatingSystem",ldap.searchvalue="Windows *Server*",ldap.attrib={operatingSystem,whencreated,OperatingSystemServicePack}' <host>

Default Option Used in script:
nmap   -p 389  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-389[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="389"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ldap-search -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ldap(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ldap-search -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ldap(host_ip,desc)
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