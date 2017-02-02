def smb(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip

    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for  SMB,:
     [1] smb-brute
     [2] smb-enum-domains
     [3] smb-enum-groups
     [4] smb-enum-processes
     [5] smb-enum-sessions
     [6] smb-enum-shares
     [7] smb-enum-users
     [8] smb-flood
     [9] smb-ls
    [10] smb-mbenum
    [11] smb-os-discovery
    [12] smb-print-text
    [13] smb-psexec
    [14] smb-security-mode
    [15] smb-server-stats
    [16] smb-system-info
    [17] smb-vuln-conficker
    [18] smb-vuln-cve2009-3103
    [19] smb-vuln-ms06-025
    [20] smb-vuln-ms07-029
    [21] smb-vuln-ms08-067
    [22] smb-vuln-ms10-054
    [23] smb-vuln-ms10-061
    [24] smb-vuln-regsvc-dos
    [25] smbv2-enabled
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-brute

Script types: hostrule
Categories: intrusive, brute
Download: http://nmap.org/svn/scripts/smb-brute.nse

User Summary
Attempts to guess username/password combinations over SMB, storing discovered combinations for use in other scripts.

Script Arguments
smblockout
This argument will force the script to continue if it locks out an account or thinks it will lock out an account.
canaries
Sets the number of tests to do to attempt to lock out the first account. This will lock out the first account without
locking out the rest of the accounts. The default is 3, which will only trigger strict lockouts, but will also bump
the canary account up far enough to detect a lockout well before other accounts are hit.
brutelimit
Limits the number of usernames checked in the script. In some domains, it's possible to end up with 10,000+ usernames
on each server. By default, this will be 5000, which should be higher than most servers and also prevent infinite loops
or other weird things. This will only affect the user list pulled from the server, not the username list.
passdb, unpwdb.passlimit, unpwdb.timelimit, unpwdb.userlimit, userdb
See the documentation for the unpwdb library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-brute.nse -p445 <host>
sudo nmap -sU -sS --script smb-brute.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-brute -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-enum-domains

Script types: hostrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/smb-enum-domains.nse

User Summary
Attempts to enumerate domains on a system, along with their policies. This generally requires credentials, except
against Windows 2000. In addition to the actual domain, the "Builtin" domain is generally displayed. Windows returns
this in the list of domains, but its policies don't appear to be used anywhere.

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-enum-domains.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-domains.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-domains -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-domains -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-enum-groups

Script types: hostrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/smb-enum-groups.nse

User Summary
Obtains a list of groups from the remote Windows system, as well as a list of the group's users. This works similarly
to enum.exe with the /G switch.
The following MSRPC functions in SAMR are used to find a list of groups and the RIDs of their users. Keep in mind that
MSRPC refers to groups as "Aliases".
    Bind: bind to the SAMR service.
    Connect4: get a connect_handle.
    EnumDomains: get a list of the domains.
    LookupDomain: get the RID of the domains.
    OpenDomain: get a handle for each domain.
    EnumDomainAliases: get the list of groups in the domain.
    OpenAlias: get a handle to each group.
    GetMembersInAlias: get the RIDs of the members in the groups.
    Close: close the alias handle.
    Close: close the domain handle.
    Close: close the connect handle.

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-enum-users.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-groups -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-groups -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-enum-processes

Script types: hostrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/smb-enum-processes.nse

User Summary
Pulls a list of processes from the remote server over SMB. This will determine all running processes, their process IDs,
and their parent processes. It is done by querying the remote registry service, which is disabled by default on Vista;
on all other Windows versions, it requires Administrator privileges.
Since this requires administrator privileges, it isn't especially useful for a penetration tester, since they can effectively
do the same thing with metasploit or other tools. It does, however, provide for a quick way to get process lists for a bunch
of systems at the same time.

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-enum-processes.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-processes.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-processes -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-processes -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-enum-sessions

Script types: hostrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/smb-enum-sessions.nse

User Summary
Enumerates the users logged into a system either locally or through an SMB share. The local users can be logged on
either physically on the machine, or through a terminal services session. Connections to a SMB share are, for example,
people connected to fileshares or making RPC calls. Nmap's connection will also show up, and is generally identified by
the one that connected "0 seconds ago".

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-enum-sessions.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-sessions.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-sessions -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-sessions -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-enum-shares

Script types: hostrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/smb-enum-shares.nse

User Summary
Attempts to list shares using the srvsvc.NetShareEnumAll MSRPC function and retrieve more information about them using
srvsvc.NetShareGetInfo. If access to those functions is denied, a list of common share names are checked.
Finding open shares is useful to a penetration tester because there may be private files shared, or, if it's writable,
it could be a good place to drop a Trojan or to infect a file that's already there. Knowing where the share is could make
those kinds of tests more useful, except that determining where the share is requires administrative privileges already.
Running NetShareEnumAll will work anonymously against Windows 2000, and requires a user-level account on any other Windows
version. Calling NetShareGetInfo requires an administrator account on all versions of Windows up to 2003, as well as Windows
Vista and Windows 7, if UAC is turned down.
Even if NetShareEnumAll is restricted, attempting to connect to a share will always reveal its existence. So, if NetShareEnumAll
fails, a pre-generated list of shares, based on a large test network, are used. If any of those succeed, they are recorded.
After a list of shares is found, the script attempts to connect to each of them anonymously, which divides them into "anonymous",
for shares that the NULL user can connect to, or "restricted", for shares that require a user account.

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-enum-shares.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-shares -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-shares -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File smb-enum-users

Script types: hostrule
Categories: auth, intrusive
Download: http://nmap.org/svn/scripts/smb-enum-users.nse

User Summary
Attempts to enumerate the users on a remote Windows system, with as much information as possible, through
two different techniques (both over MSRPC, which uses port 445 or 139; see smb.lua). The goal of this script
is to discover all user accounts that exist on a remote system. This can be helpful for administration, by
seeing who has an account on a server, or for penetration testing or network footprinting, by determining
which accounts exist on a system.
A penetration tester who is examining servers may wish to determine the purpose of a server. By getting a
list of who has access to it, the tester might get a better idea (if financial people have accounts,
it probably relates to financial information). Additionally, knowing which accounts exist on a system (
or on multiple systems) allows the pen-tester to build a dictionary of possible usernames for bruteforces,
such as a SMB bruteforce or a Telnet bruteforce. These accounts may be helpful for other purposes,
such as using the accounts in Web applications on this or other servers.

Script Arguments
samronly
If set, script will only query a list of users using a SAMR lookup. This is much quieter than LSA lookups, so enable this if you want stealth. Generally, however, you'll get better results by using the default options.
lsaonly
If set, script will only enumerate using an LSA bruteforce (requires less access than samr). Only set if you know what you're doing, you'll get better results by using the default options.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage

nmap --script smb-enum-users.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-users -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-enum-users -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-flood

Script types: hostrule
Categories: intrusive, dos
Download: http://nmap.org/svn/scripts/smb-flood.nse

User Summary
Exhausts a remote SMB server's connection limit by by opening as many connections as we can. Most implementations
of SMB have a hard global limit of 11 connections for user accounts and 10 connections for anonymous. Once that limit
is reached, further connections are denied. This script exploits that limit by taking up all the connections and holding them.
This works better with a valid user account, because Windows reserves one slot for valid users. So, no matter
how many anonymous connections are taking up spaces, a single valid user can still log in.
This is *not* recommended as a general purpose script, because a) it is designed to harm the server and has no useful output,
 and b) it never ends (until timeout).

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-flood.nse -p445 <host>
sudo nmap -sU -sS --script smb-flood.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-flood -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-flood -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-ls

Script types: hostrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/smb-ls.nse

User Summary
Attempts to retrieve useful information about files shared on SMB volumes. The output is intended to resemble
the output of the UNIX ls command.

Script Arguments
smb-ls.path
the path, relative to the share to list the contents from (default: root of the share)
smb-ls.pattern
the search pattern to execute (default: *)
smb-ls.share
(or smb-ls.shares) the share (or a colon-separated list of shares) to connect to (default: use shares found by smb-enum-shares)
smb-ls.checksum
download each file and calculate a checksum (default: false)
ls.checksum, ls.empty, ls.errors, ls.human, ls.maxdepth, ls.maxfiles
See the documentation for the ls library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 445 <ip> --script smb-ls --script-args 'share=c$,path=\temp'
nmap -p 445 <ip> --script smb-enum-shares,smb-ls


Default Option Used in script:
nmap -sV -p 445 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smb-ls -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script smb-ls -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "10":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-mbenum

Script types: hostrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/smb-mbenum.nse

User Summary
Queries information managed by the Windows Master Browser.

Script Arguments
smb-mbenum.format
(optional) if set, changes the format of the result returned by the script. There are three possible formats: 1. Ordered by type horizontally 2. Ordered by type vertically 3. Ordered by type vertically with details (default)
smb-mbenum.domain
(optional) if not specified, lists the domain of the queried browser
smb-mbenum.filter
(optional) if set, queries the browser for a specific type of server (@see ServerTypes)
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 445 <host> --script smb-mbenum

Default Option Used in script:
nmap -sV -p 445 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smb-mbenum -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script smb-mbenum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "11":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-os-discovery

Script types: hostrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/smb-os-discovery.nse

User Summary
Attempts to determine the operating system, computer name, domain, workgroup, and current time over the SMB protocol
(ports 445 or 139). This is done by starting a session with the anonymous account (or with a proper user account, if
one is given; it likely doesn't make a difference); in response to a session starting, the server will send back all
this information.
The following fields may be included in the output, depending on the circumstances (e.g. the workgroup name is mutually
exclusive with domain and forest names) and the information available:
    OS
    Computer name
    Domain name
    Forest name
    FQDN
    NetBIOS computer name
    NetBIOS domain name
    Workgroup
    System time

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-os-discovery.nse -p445 127.0.0.1
sudo nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 127.0.0.1


Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port- U:137,T:139[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port=" U:137,T:139"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-os-discovery -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smb-os-discovery -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "12":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-print-text

Script types: hostrule
Categories: intrusive
Download: http://nmap.org/svn/scripts/smb-print-text.nse

User Summary
Attempts to print text on a shared printer by calling Print Spooler Service RPC functions.
In order to use the script, at least one printer needs to be shared over SMB. If no printer is specified,
script tries to enumerate existing ones by calling LANMAN API which might not be always available.
LANMAN is available by default on Windows XP, but not on Vista or Windows 7 for example. In that case,
you need to specify printer share name manually using printer script argument. You can find out available
shares by using smb-enum-shares script.
Later versions of Windows require valid credentials by default which you can specify trough smb library arguments smbuser and smbpassword or other options.

Script Arguments
text
Text to print. Either text or filename need to be specified.
filename
File to read text from (ASCII only).
printer
Printer share name. Optional, by default script tries to enumerate available printer shares.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap  -p 445 <target> --script=smb-print-text  --script-args="text=0wn3d"


Default Option Used in script:
nmap -sV -p 445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script smb-print-text -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smb-print-text -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "13":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-psexec

Script types: hostrule
Categories: intrusive
Download: http://nmap.org/svn/scripts/smb-psexec.nse

User Summary
Implements remote process execution similar to the Sysinternals' psexec tool, allowing a user to run a series of programs
on a remote machine and read the output. This is great for gathering information about servers, running the same tool on a
range of system, or even installing a backdoor on a collection of computers.

Example Usage
nmap --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p445 <host>
sudo nmap -sU -sS --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>]
      -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script smb-psexec -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smb-psexec -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "14":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-security-mode

Script types: hostrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/smb-security-mode.nse

User Summary
Returns information about the SMB security level determined by SMB.

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-security-mode.nse -p445 127.0.0.1
sudo nmap -sU -sS --script smb-security-mode.nse -p U:137,T:139 127.0.0.1


Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script smb-security-mode -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smb-security-mode -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "15":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-server-stats

Script types: hostrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/smb-server-stats.nse

User Summary
Attempts to grab the server's statistics over SMB and MSRPC, which uses TCP ports 445 or 139.
An administrator account is required to pull these statistics on most versions of Windows,
and Vista and above require UAC to be turned down.
Some of the numbers returned here don't feel right to me, but they're definitely the numbers
that Windows returns. Take the values here with a grain of salt.
These statistics are found using a single call to a SRVSVC function, NetServerGetStatistics.
This packet is parsed incorrectly by Wireshark, up to version 1.0.3 (and possibly higher).

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-server-stats.nse -p445 <host>
sudo nmap -sU -sS --script smb-server-stats.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script smb-server-stats -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smb-server-stats -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "16":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-system-info

Script types: hostrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/smb-system-info.nse

User Summary
Pulls back information about the remote system from the registry. Getting all of the information requires an
administrative account, although a user account will still get a lot of it. Guest probably won't get any,
nor will anonymous. This goes for all operating systems, including Windows 2000.
Windows Vista disables remote registry access by default, so unless it was enabled, this script won't work.
If you know of more information stored in the Windows registry that could be interesting,
post a message to the nmap-dev mailing list and I (Ron Bowes) will add it to my todo list.
Adding new checks to this is extremely easy.

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smb-system-info.nse -p445 <host>
sudo nmap -sU -sS --script smb-system-info.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap -sV -sS -sU -p U:137,T:139,445 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script smb-system-info -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script smb-system-info -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "17":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-vuln-conficker

Script types: hostrule
Categories: intrusive, exploit, dos, vuln
Download: http://nmap.org/svn/scripts/smb-vuln-conficker.nse

User Summary
Detects Microsoft Windows systems infected by the Conficker worm.
This check is dangerous and it may crash systems.
Based loosely on the Simple Conficker Scanner, found here:
-- http://iv.cs.uni-bonn.de/wg/cs/applications/containing-conficker/
This check was previously part of smb-check-vulns.

Script Arguments
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script smb-vuln-conficker.nse -p445 <host>
nmap -sU --script smb-vuln-conficker.nse -p T:139 <host>

Default Option Used in script:
nmap -sV  -sU -p U:137,T:139,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script smb-vuln-conficker -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script smb-vuln-conficker -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "18":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-vuln-cve2009-3103

Script types: hostrule
Categories: intrusive, exploit, dos, vuln
Download: http://nmap.org/svn/scripts/smb-vuln-cve2009-3103.nse

User Summary
Detects Microsoft Windows systems vulnerable to denial of service (CVE-2009-3103).
This script will crash the service if it is vulnerable.
The script performs a denial-of-service against the vulnerability disclosed in CVE-2009-3103.
This works against Windows Vista and some versions of Windows 7, and causes a bluescreen if successful.
The proof-of-concept code at http://seclists.org/fulldisclosure/2009/Sep/39 was used, with one small change.
This check was previously part of smb-check-vulns.

Script Arguments
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script smb-vuln-cve2009-3103.nse -p445 <host>
nmap -sU --script smb-vuln-cve2009-3103.nse -p U:137,T:139 <host>


Default Option Used in script:
nmap  -sV -sU -p U:137,T:139,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV   -sU --script smb-vuln-cve2009-3103 -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script smb-vuln-cve2009-3103 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "19":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-vuln-ms06-025

Script types: hostrule
Categories: intrusive, exploit, dos, vuln
Download: http://nmap.org/svn/scripts/smb-vuln-ms06-025.nse

User Summary
Detects Microsoft Windows systems with Ras RPC service vulnerable to MS06-025.
MS06-025 targets the RasRpcSumbitRequest() RPC method which is a part of RASRPC interface that serves as a RPC service
for configuring and getting information from the Remote Access and Routing service. RASRPC can be accessed using either
"\ROUTER" SMB pipe or the "\SRVSVC" SMB pipe (usually on Windows XP machines). This is in RPC world known as "ncan_np" RPC transport.
RasRpcSumbitRequest() method is a generic method which provides different functionalities according to the RequestBuffer structure
and particularly the RegType field within that structure. RegType field is of enum ReqTypes type. This enum type lists all
the different available operation that can be performed using the RasRpcSubmitRequest() RPC method. The one particular operation
that this vuln targets is the REQTYPE_GETDEVCONFIG request to get device information on the RRAS.
This script was previously part of smb-check-vulns.

Script Arguments
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script smb-vuln-ms06-025.nse -p445 <host>
nmap -sU --script smb-vuln-ms06-025.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap  -sV -sU -p U:137,T:139,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script smb-vuln-ms06-025 -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script smb-vuln-ms06-025 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "20":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-vuln-ms07-029

Script types: hostrule
Categories: intrusive, exploit, dos, vuln
Download: http://nmap.org/svn/scripts/smb-vuln-ms07-029.nse

User Summary
Detects Microsoft Windows systems with Dns Server RPC vulnerable to MS07-029.
MS07-029 targets the R_DnssrvQuery() and R_DnssrvQuery2() RPC method which isa part of
DNS Server RPC interface that serves as a RPC service for configuring and getting information
from the DNS Server service. DNS Server RPC service can be accessed using "\dnsserver" SMB named pipe.
The vulnerability is triggered when a long string is send as the "zone" parameter which causes the buffer
overflow which crashes the service.
This check was previously part of smb-check-vulns.

Script Arguments
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script smb-vuln-ms07-029.nse -p445 <host>
nmap -sU --script smb-vuln-ms07-029.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap  -sV -sU -p U:137,T:139,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script smb-vuln-ms07-029 -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script smb-vuln-ms07-029 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "21":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-vuln-ms08-067

Script types: hostrule
Categories: intrusive, exploit, dos, vuln
Download: http://nmap.org/svn/scripts/smb-vuln-ms08-067.nse

User Summary
Detects Microsoft Windows systems vulnerable to the remote code execution vulnerability known as MS08-067.
This check is dangerous and it may crash systems.
On a fairly wide scan conducted by Brandon Enright, we determined that on average, a vulnerable system is more likely
to crash than to survive the check. Out of 82 vulnerable systems, 52 crashed. Please consider this before running the script.
This check was previously part of smb-check-vulns.nse.

Script Arguments
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script smb-vuln-ms08-067.nse -p445 <host>
nmap -sU --script smb-vuln-ms08-067.nse -p U:137 <host>

Default Option Used in script:
nmap  -sV -sU -p U:137,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script smb-vuln-ms08-067 -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script smb-vuln-ms08-067 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "22":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-vuln-ms10-054

Script types: hostrule
Categories: vuln, intrusive, dos
Download: http://nmap.org/svn/scripts/smb-vuln-ms10-054.nse

User Summary
Tests whether target machines are vulnerable to the ms10-054 SMB remote memory corruption vulnerability.
The vulnerable machine will crash with BSOD.
The script requires at least READ access right to a share on a remote machine. Either with guest credentials or
with specified username/password.

Script Arguments
smb-vuln-ms10-054.share
Share to connect to (defaults to SharedDocs)
unsafe
Required to run the script, "safety swich" to prevent running it by accident
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap  -p 445 <target> --script=smb-vuln-ms10-054 --script-args unsafe

Default Option Used in script:
nmap  -sV -p 445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script smb-vuln-ms10-054 -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script smb-vuln-ms10-054 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "23":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-vuln-ms10-061

Script types: hostrule
Categories: vuln, intrusive
Download: http://nmap.org/svn/scripts/smb-vuln-ms10-061.nse

User Summary
Tests whether target machines are vulnerable to ms10-061 Printer Spooler impersonation vulnerability.
This vulnerability was used in Stuxnet worm. The script checks for the vuln in a safe way without a
possibility of crashing the remote system as this is not a memory corruption vulnerability. In order
for the check to work it needs access to at least one shared printer on the remote system. By default
it tries to enumerate printers by using LANMAN API which on some systems is not available by default.
In that case user should specify printer share name as printer script argument. To find a printer share,
smb-enum-shares can be used. Also, on some systems, accessing shares requires valid credentials which can
be specified with smb library arguments smbuser and smbpassword.

Script Arguments
printer
Printer share name. Optional, by default script tries to enumerate available printer shares.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap  -p 445 <target> --script=smb-vuln-ms10-061

Default Option Used in script:
nmap  -sV -p 445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script smb-vuln-ms10-061 -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script smb-vuln-ms10-061 -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "24":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smb-vuln-regsvc-dos

Script types: hostrule
Categories: intrusive, exploit, dos, vuln
Download: http://nmap.org/svn/scripts/smb-vuln-regsvc-dos.nse

User Summary
Checks if a Microsoft Windows 2000 system is vulnerable to a crash in regsvc caused by a
null pointer dereference. This check will crash the service if it is vulnerable and requires
a guest account or higher to work.
The vulnerability was discovered by Ron Bowes while working on smb-enum-sessions and was reported
to Microsoft (Case #MSRC8742).
This check was previously part of smb-check-vulns.

Script Arguments
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script smb-vuln-regsvc-dos.nse -p445 <host>
nmap -sU --script smb-vuln-regsvc-dos.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap  -sV -sU -p U:137,T:139,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script smb-vuln-regsvc-dos -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sU --script smb-vuln-regsvc-dos -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "25":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File smbv2-enabled

Script types: hostrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/smbv2-enabled.nse

User Summary
Checks whether or not a server is running the SMBv2 protocol.

Script Arguments
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script smbv2-enabled.nse -p445 <host>
sudo nmap -sU -sS --script smbv2-enabled.nse -p U:137,T:139 <host>

Default Option Used in script:
nmap  -sV -sS -sU -p U:137,T:139,445  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-U:137,T:139,445[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="U:137,T:139,445"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smbv2-enabled -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV -sS -sU --script smbv2-enabled -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            smb(host_ip,desc)
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