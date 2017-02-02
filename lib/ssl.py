def ssl(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for SSL/TLS:
     [1] ssl-ccs-injection
     [2] ssl-cert
     [3] ssl-date
     [4] sl-dh-params
     [5] ssl-enum-ciphers
     [6] ssl-google-cert-catalog
     [7] ssl-heartbleed
     [8] ssl-known-key
     [9] ssl-poodle
     [10] sslv2-drown
     [11] sslv2
     [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssl-ccs-injection

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/ssl-ccs-injection.nse

User Summary
Detects whether a server is vulnerable to the SSL/TLS "CCS Injection" vulnerability (CVE-2014-0224),
first discovered by Masashi Kikuchi. The script is based on the ccsinjection.c code authored by Ramon de C
Valle (https://gist.github.com/rcvalle/71f4b027d61a78c42607)

In order to exploit the vulnerablity, a MITM attacker would effectively do the following:
o Wait for a new TLS connection, followed by the ClientHello ServerHello handshake messages.
o Issue a CCS packet in both the directions, which causes the OpenSSL code to use a zero length pre master secret key.
The packet is sent to both ends of the connection. Session Keys are derived using a zero length pre master secret key, and
future session keys also share this weakness.
o Renegotiate the handshake parameters.
o The attacker is now able to decrypt or even modify the packets in transit.

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -p 443 --script ssl-ccs-injection <target>

Default Option Used in script:
nmap  -sV -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ssl-ccs-injection -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script ssl-ccs-injection -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssl-cert

Script types: portrule
Categories: default, safe, discovery
Download: http://nmap.org/svn/scripts/ssl-cert.nse

User Summary
Retrieves a server's SSL certificate. The amount of information printed about the certificate depends
on the verbosity level. With no extra verbosity, the script prints the validity period and the commonName, 
organizationName, stateOrProvinceName, and countryName of the subject.

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

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
            subprocess.call('nmap  -sV --script ssl-cert'+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ssl-cert -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssl-date

Script types: portrule
Categories: discovery, safe, default
Download: http://nmap.org/svn/scripts/ssl-date.nse

User Summary
Retrieves a target host's time and date from its TLS ServerHello response.
In many TLS implementations, the first four bytes of server randomness are a Unix timestamp.
The script will test whether this is indeed true and report the time only if it passes this test.


Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap <target> --script=ssl-date

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ssl-date'+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ssl-date -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssl-dh-params

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/ssl-dh-params.nse

User Summary
Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services.
This script simulates SSL/TLS handshakes using ciphersuites that have ephemeral Diffie-Hellman as the
key exchange algorithm.
Diffie-Hellman MODP group parameters are extracted and analyzed for vulnerability to Logjam (CVE 2015-4000)
and other weaknesses.
Opportunistic STARTTLS sessions are established on services that support them.

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap --script ssl-dh-params <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script ssl-dh-params '+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script ssl-dh-params  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssl-enum-ciphers

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/ssl-enum-ciphers.nse

User Summary
This script repeatedly initiates SSLv3/TLS connections, each time trying a new cipher or compressor while recording whether a host accepts
or rejects it. The end result is a list of all the ciphersuites and compressors that a server accepts.

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script ssl-enum-ciphers -p 443 <host>

Default Option Used in script:
nmap  -sV -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ssl-enum-ciphers -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script ssl-enum-ciphers -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssl-google-cert-catalog

Script types: portrule
Categories: safe, discovery, external
Download: http://nmap.org/svn/scripts/ssl-google-cert-catalog.nse

User Summary
Queries Google's Certificate Catalog for the SSL certificates retrieved from target hosts.
The Certificate Catalog provides information about how recently and for how long Google has
seen the given certificate. If a certificate doesn't appear in the database, despite being correctly
signed by a well-known CA and having a matching domain name, it may be suspicious.

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, m
ssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap -p 443 --script ssl-cert,ssl-google-cert-catalog <host>>

Default Option Used in script:
nmap  -sV -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script ssl-google-cert-catalog -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script ssl-google-cert-catalog -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssl-heartbleed

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/ssl-heartbleed.nse

User Summary
Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160). The code is based on the Python script ssltest.py authored by Jared Stafford (jspenguin@jspenguin.org)

Script Arguments
ssl-heartbleed.protocols
(default tries all) TLS 1.0, TLS 1.1, or TLS 1.2
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port,
mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -p 443 --script ssl-heartbleed <target>

Default Option Used in script:
nmap  -sV -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  ssl-heartbleed -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  ssl-heartbleed -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssl-known-key

Script types: portrule
Categories: safe, discovery, vuln, default
Download: http://nmap.org/svn/scripts/ssl-known-key.nse

User Summary
Checks whether the SSL certificate used by a host has a fingerprint that matches an included database of problematic keys.
The only databases currently checked are the LittleBlackBox 0.1 database of compromised keys from various devices
and some keys reportedly used by the Chinese state-sponsored hacking division APT1 (https://www.mandiant.com/blog/md5-sha1/).
However, any file of fingerprints will serve just as well. For example, this could be used to find weak Debian OpenSSL keys
using the widely available (but too large to include with Nmap) list.

Script Arguments
ssl-known-key.fingerprintfile
Specify a different file to read fingerprints from.
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

Example Usage
nmap --script ssl-known-key -p 443 <host>

Default Option Used in script:
nmap  -sV -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  ssl-known-key -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  ssl-known-key -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File ssl-poodle

Script types: portrule
Categories: vuln, safe
Download: http://nmap.org/svn/scripts/ssl-poodle.nse

User Summary
Checks whether SSLv3 CBC ciphers are allowed (POODLE)
Run with -sV to use Nmap's service scan to detect SSL/TLS on non-standard ports. Otherwise, ssl-poodle will
only run on ports that are commonly used for SSL.
POODLE is CVE-2014-3566. All implementations of SSLv3 that accept CBC ciphersuites are vulnerable. For speed of detection,
this script will stop after the first CBC ciphersuite is discovered. If you want to enumerate all CBC ciphersuites,
you can use Nmap's own ssl-enum-ciphers to do a full audit of your TLS ciphersuites.

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port,
mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --version-light --script ssl-poodle -p 443 <host>

Default Option Used in script:
nmap  -sV -p 443 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-443[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="443"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV --script  ssl-poodle -p'+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")        
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sV  --script  ssl-poodle -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)        
            sys.exit(exit_msg)
    elif option == "10":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File sslv2-drown

Script types: portrule
Categories: intrusive, vuln
Download: http://nmap.org/svn/scripts/sslv2-drown.nse

User Summary
Determines whether the server supports SSLv2, what ciphers it supports and tests for CVE-2015-3197, CVE-2016-0703 and
CVE-2016-0800 (DROWN)

Script Arguments
mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
vulns.showall
See the documentation for the vulns library.

Example Usage
nmap -sV --script=sslv2-drown <target>

Default Option Used in script:
nmap -sV --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sV --script sslv2-drown '+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script sslv2-drown  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "11":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File sslv2

Script types: portrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/sslv2.nse
User Summary

Determines whether the server supports obsolete and less secure SSLv2, and discovers which ciphers it supports.
Script Arguments

mssql.domain, mssql.instance-all, mssql.instance-name, mssql.instance-port, mssql.password, mssql.protocol, mssql.scanned-ports-only, mssql.timeout, mssql.username
See the documentation for the mssql library.
smtp.domain
See the documentation for the smtp library.
randomseed, smbbasic, smbport, smbsign
See the documentation for the smb library.
smbdomain, smbhash, smbnoguest, smbpassword, smbtype, smbusername
See the documentation for the smbauth library.

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
            subprocess.call('nmap  -sV --script sslv2 '+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script sslv2  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            ssl(host_ip,desc)
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
    