def dns(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for DNS:
      [1] dns-blacklist
      [2] dns-brute
      [3] dns-cache-snoop
      [4] dns-check-zone
      [5] dns-client-subnet-scan
      [6] dns-fuzz
      [7] dns-ip6-arpa-scan
      [8] dns-nsec-enum
      [9] dns-nsec3-enum
     [10] dns-nsid
     [11] dns-random-srcport
     [12] dns-random-txid
     [13] dns-recursion
     [14] dns-service-discovery
     [15] dns-srv-enum
     [16] dns-update
     [17] dns-zeustracker
     [18] dns-zone-transfer
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m

File dns-blacklist

Script types: prerule, hostrule
Categories: external, safe
Download: http://nmap.org/svn/scripts/dns-blacklist.nse

User Summary
Checks target IP addresses against multiple DNS anti-spam and open proxy blacklists and returns a list of services
for which an IP has been flagged. Checks may be limited by service category (eg: SPAM, PROXY) or to a specific service name.

Script Arguments:
dns-blacklist.services
string containing a comma-separated list of services to query. (default: all)
dns-blacklist.ip
string containing the IP to check only needed if running the script as a prerule.
dns-blacklist.list
lists all services that are available for a certain category.
dns-blacklist.category
string containing the service category to query eg. spam or proxy (default: all)
dns-blacklist.mode
string containing either "short" or "long" long mode can sometimes provide additional information to why an IP has been
blacklisted. (default: long)

Example Usage
nmap --script dns-blacklist --script-args='dns-blacklist.ip=<ip>'
or
nmap -sn <ip> --script dns-blacklist

Default Option Used in script:
nmap  -sn --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn --script dns-blacklist'+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script dns-blacklist -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "2":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-brute

Script types: prerule, hostrule
Categories: intrusive, discovery
Download: http://nmap.org/svn/scripts/dns-brute.nse

User Summary
Attempts to enumerate DNS hostnames by brute force guessing of common subdomains. With the dns-brute.srv argument,
dns-brute will also try to enumerate common DNS SRV records.

Script Arguments
dns-brute.threads
Thread to use (default 5).
dns-brute.srvlist
The filename of a list of SRV records to try. Defaults to "nselib/data/dns-srv-names"
dns-brute.hostlist
The filename of a list of host strings to try. Defaults to "nselib/data/vhosts-default.lst"
dns-brute.srv
Perform lookup for SRV records
dns-brute.domain
Domain name to brute force if no host is specified
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script dns-brute --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80
nmap --script dns-brute www.foo.com

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script dns-brute '+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script dns-brute -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "3":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-cache-snoop

Script types: portrule
Categories: intrusive, discovery
Download: http://nmap.org/svn/scripts/dns-cache-snoop.nse

User Summary
Performs DNS cache snooping against a DNS server.
There are two modes of operation, controlled by the dns-cache-snoop.mode script argument. In nonrecursive mode
(the default), queries are sent to the server with the RD (recursion desired) flag set to 0. The server should respond
positively to these only if it has the domain cached. In timed mode, the mean and standard deviation response times for
a cached domain are calculated by sampling the resolution of a name (www.google.com) several times. Then, each domain is
resolved and the time taken compared to the mean. If it is less than one standard deviation over the mean, it is considered
cached. The timed mode inserts entries in the cache and can only be used reliably once.
The default list of domains to check consists of the top 50 most popular sites, each site being listed twice, once with
"www." and once without. Use the dns-cache-snoop.domains script argument to use a different list.

Script Arguments
dns-cache-snoop.mode
which of two supported snooping methods to use. nonrecursive, the default, checks if the server returns results for non-recursive queries. Some servers may disable this. timed measures the difference in time taken to resolve cached and non-cached hosts. This mode will pollute the DNS cache and can only be used once reliably.
dns-cache-snoop.domains
an array of domain to check in place of the default list.

Example Usage
nmap -sU -p 53 --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={host1,host2,host3}' <target>

Default Option Used in script:
nmap -sU -p 53 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-53[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="53"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sU --script dns-cache-snoop  -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip +"-"+file_name+".txt"
            subprocess.call('nmap -sU --script dns-cache-snoop -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "4":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-check-zone

Script types: hostrule
Categories: discovery, safe, external
Download: http://nmap.org/svn/scripts/dns-check-zone.nse
User Summary
Checks DNS zone configuration against best practices, including RFC 1912. The configuration checks are
divided into categories which each have a number of different tests.

Script Arguments
dns-check-zone.domain
the dns zone to check

Example Usage
nmap -sn -Pn ns1.example.com --script dns-check-zone --script-args='dns-check-zone.domain=example.com'

Default Option Used in script:
nmap -sn -Pn --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn -Pn --script dns-check-zone  '+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn -Pn --script dns-check-zone -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "5":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-client-subnet-scan

Script types: prerule, portrule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/dns-client-subnet-scan.nse

User Summary
Performs a domain lookup using the edns-client-subnet option which allows clients to specify the subnet that queries
supposedly originate from. The script uses this option to supply a number of geographically distributed locations in an attempt
to enumerate as many different address records as possible. The script also supports requests using a given subnet.

http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-00

Script Arguments
dns-client-subnet.mask
[optional] The number of bits to use as subnet mask (default: 24)
dns-client-subnet.address
The client subnet address to use
dns-client-subnet.domain
The domain to lookup eg. www.example.org
dns-client-subnet.nameserver
[optional] nameserver to use. (default = host.ip)

Example Usage
nmap -sU -p 53 --script dns-client-subnet-scan  --script-args \
    'dns-client-subnet-scan.domain=www.example.com, \
    dns-client-subnet-scan.address=192.168.0.1 \
    [,dns-client-subnet.nameserver=8.8.8.8] \
    [,dns-client-subnet.mask=24]' <target>
nmap --script dns-client-subnet-scan --script-args \
    'dns-client-subnet-scan.domain=www.example.com, \
    dns-client-subnet-scan.address=192.168.0.1 \
    dns-client-subnet.nameserver=8.8.8.8, \
    [,dns-client-subnet.mask=24]'

Default Option Used in script:
nmap -sn --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU  --script dns-client-subnet-scan'+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script dns-client-subnet-scan -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "6":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-fuzz

Script types: portrule
Categories: fuzzer, intrusive
Download: http://nmap.org/svn/scripts/dns-fuzz.nse

User Summary
Launches a DNS fuzzing attack against DNS servers.
The script induces errors into randomly generated but valid DNS packets. The packet template that we use includes
one uncompressed and one compressed name.
Use the dns-fuzz.timelimit argument to control how long the fuzzing lasts. This script should be run for a long time.
It will send a very large quantity of packets and thus it's pretty invasive, so it should only be used against private DNS servers
as part of a software development lifecycle.

Script Arguments
dns-fuzz.timelimit
How long to run the fuzz attack. This is a number followed by a suffix: s for seconds, m for minutes, and h for hours. Use 0 for an unlimited amount of time. Default: 10m.

Example Usage
nmap -sU --script dns-fuzz --script-args timelimit=2h <target>

Default Option Used in script:
nmap -sU --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU  --script dns-fuzz'+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script dns-fuzz -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "7":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-ip6-arpa-scan

Script types: prerule
Categories: intrusive, discovery
Download: http://nmap.org/svn/scripts/dns-ip6-arpa-scan.nse

User Summary
Performs a quick reverse DNS lookup of an IPv6 network using a technique which analyzes DNS server response codes
to dramatically reduce the number of queries needed to enumerate large networks.
The technique essentially works by adding an octet to a given IPv6 prefix and resolving it. If the added octet is correct,
the server will return NOERROR, if not a NXDOMAIN result is received.
The technique is described in detail on Peter's blog: http://7bits.nl/blog/2012/03/26/finding-v6-hosts-by-efficiently-mapping-ip6-arpa

Script Arguments
prefix
the ip6 prefix to scan
mask
the ip6 mask to start scanning from

Example Usage
nmap --script dns-ip6-arpa-scan --script-args='prefix=2001:0DB8::/48'>

Default Option Used in script:
nmap --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-no port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script dns-ip6-arpa-scan'+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script dns-ip6-arpa-scan -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "8":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-nsec-enum

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/dns-nsec-enum.nse
User Summary

Enumerates DNS names using the DNSSEC NSEC-walking technique.

Output is arranged by domain. Within a domain, subzones are shown with increased indentation.

The NSEC response record in DNSSEC is used to give negative answers to queries, but it has the side effect of allowing enumeration of all names, much like a zone transfer. This script doesn't work against servers that use NSEC3 rather than NSEC; for that, see dns-nsec3-enum.

Script Arguments
dns-nsec-enum.domains
The domain or list of domains to enumerate. If not provided, the script will make a guess based on the name of the target.

Example Usage
nmap -sSU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=example.com <target>

Default Option Used in script:
nmap -sSU-p 53 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-53[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="53"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sSU --script dns-nsec-enum -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sSU --script dns-nsec-enum -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "9":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-nsec3-enum

Script types: portrule
Categories: discovery, intrusive
Download: http://nmap.org/svn/scripts/dns-nsec3-enum.nse

User Summary
Tries to enumerate domain names from the DNS server that supports DNSSEC NSEC3 records.
The script queries for nonexistant domains until it exhausts all domain ranges keeping track of hashes.
At the end, all hashes are printed along with salt and number of iterations used. This technique is known as "NSEC3 walking".
That info should then be fed into an offline cracker, like unhash from http://dnscurve.org/nsec3walker.html, to bruteforce the
actual names from the hashes. Assuming that the script output was written into a text file hashes.txt like:

domain example.com
salt 123456
iterations 10
nexthash d1427bj0ahqnpi4t0t0aaun18oqpgcda vhnelm23s1m3japt7gohc82hgr9un2at
nexthash k7i4ekvi22ebrim5b6celtaniknd6ilj prv54a3cr1tbcvqslrb7bftf5ji5l0p8
nexthash 9ool6bk7r2diaiu81ctiemmb6n961mph nm7v0ig7h9c0agaedc901kojfj9bgabj
nexthash 430456af8svfvl98l66shhrgucoip7mi mges520acstgaviekurg3oksh9u31bmb

Run this command to recover the domain names:

# ./unhash < hashes.txt > domains.txt
names: 8
d1427bj0ahqnpi4t0t0aaun18oqpgcda ns.example.com.
found 1 private NSEC3 names (12%) using 235451 hash computations
k7i4ekvi22ebrim5b6celtaniknd6ilj vulpix.example.com.
found 2 private NSEC3 names (25%) using 35017190 hash computations

Use the dns-nsec3-enum  script to handle servers that use NSEC rather than NSEC3.
References:
http://dnscurve.org/nsec3walker.html

Script Arguments
dns-nsec3-enum.domains
The domain or list of domains to enumerate. If not provided, the script will make a guess based on the name of the target.
dns-nsec3-enum.timelimit
Sets a script run time limit. Default 30 minutes.

Example Usage
nmap  -sU -p 53 <target> --script=dns-nsec3-enum --script-args dns-nsec3-enum.domains=example.com

Default Option Used in script:
nmap -sU -p 53 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-53[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="53"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sU --script dns-nsec3-enum  -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script dns-nsec3-enum  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "10":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-nsid

Script types: portrule
Categories: discovery, default
Download: http://nmap.org/svn/scripts/dns-nsid.nsef

User Summary
Retrieves information from a DNS nameserver by requesting its nameserver ID (nsid) and asking for its id.server and version.bind values. This script performs the same queries as the following two dig commands: - dig CH TXT bind.version @target - dig +nsid CH TXT id.server @target
References: [1]http://www.ietf.org/rfc/rfc5001.txt [2]http://www.ietf.org/rfc/rfc4892.txt
Example Usage
nmap -sSU -p 53 --script dns-nsid <target>

Default Option Used in script:
nmap -sSU -p 53 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-53[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="53"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output = "-oN" + ' ' + "output/" + host_ip + "-" + file_name + ".txt"
            subprocess.call('nmap  -sSU --script dns-nsid  -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sSU --script dns-nsid  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "11":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
ile dns-random-srcport

Script types: portrule
Categories: external, intrusive
Download: http://nmap.org/svn/scripts/dns-random-srcport.nse

User Summary
Checks a DNS server for the predictable-port recursion vulnerability. Predictable source ports can make a DNS server
vulnerable to cache poisoning attacks (see CVE-2008-1447).
The script works by querying porttest.dns-oarc.net (see https://www.dns-oarc.net/oarc/services/porttest). Be aware that a
ny targets against which this script is run will be sent to and potentially recorded by one or more DNS servers and the porttest server. In addition your IP address will be sent along with the porttest query to the DNS server running on the target.
Example Usage
nmap -sU -p 53 --script=dns-random-srcport <target>

Default Option Used in script:
nmap -sSU -p 53 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-53[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="53"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sSU --script dns-random-srcport  -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sSU --script dns-random-srcport  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "12":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-random-txid

Script types: portrule
Categories: external, intrusive
Download: http://nmap.org/svn/scripts/dns-random-txid.nse

User Summary
Checks a DNS server for the predictable-TXID DNS recursion vulnerability. Predictable TXID values can make a DNS
server vulnerable to cache poisoning attacks (see CVE-2008-1447).
The script works by querying txidtest.dns-oarc.net (see https://www.dns-oarc.net/oarc/services/txidtest). Be aware
that any targets against which this script is run will be sent to and potentially recorded by one or more DNS servers and
the txidtest server. In addition your IP address will be sent along with the txidtest query to the DNS server running on the
target.

Example Usage
nmap -sU -p 53 --script=dns-random-txid <target>

Default Option Used in script:
nmap -sU -p 53 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-53[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="53"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sU --script dns-random-txid  -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script dns-random-txid  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "13":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-recursion

Script types: portrule
Categories: default, safe
Download: http://nmap.org/svn/scripts/dns-recursion.nse

User Summary
Checks if a DNS server allows queries for third-party names. It is expected that recursion will be enabled on your own internal nameservers.
Example Usage
nmap -sU -p 53 --script=dns-recursion <target>

Default Option Used in script:
nmap -sU -p 53 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-53[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="53"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sU --script dns-recursion  -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script dns-recursion  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "14":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-service-discovery

Script types: portrule
Categories: default, discovery, safe
Download: http://nmap.org/svn/scripts/dns-service-discovery.nse

User Summary
Attempts to discover target hosts' services using the DNS Service Discovery protocol.
The script first sends a query for _services._dns-sd._udp.local to get a list of services. It then sends a followup
query for each one to try to get more information.

Script Arguments
max-newtargets, newtargets
See the documentation for the target library.
dnssd.services
See the documentation for the dnssd library.

Example Usage
nmap --script=dns-service-discovery -p 5353 <target>

Default Option Used in script:
nmap -p 5353 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-5353[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="5353"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script dns-service-discovery  -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script dns-service-discovery  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "15":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-srv-enum

Script types: prerule
Categories: discovery, safe
Download: http://nmap.org/svn/scripts/dns-srv-enum.nse

User Summary
Enumerates various common service (SRV) records for a given domain name. The service records contain the hostname,
port and priority of servers for a given service. The following services are enumerated by the script: - Active Directory Global Catalog
- Exchange Autodiscovery - Kerberos KDC Service - Kerberos Passwd Change Service - LDAP Servers - SIP Servers - XMPP S2S - XMPP C2S

Script Arguments
dns-srv-enum.domain
string containing the domain to query
dns-srv-enum.filter
string containing the service to query (default: all)
max-newtargets, newtargets
See the documentation for the target library.

Example Usage
nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='example.com'"

Default Option Used in script:
nmap  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script dns-srv-enum '+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script dns-srv-enum  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "16":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-update

Script types: portrule
Categories: vuln, intrusive
Download: http://nmap.org/svn/scripts/dns-update.nse
User Summary

Attempts to perform a dynamic DNS update without authentication.

Either the test or both the hostname and ip script arguments are required. Note that the test function will probably fail due to using a static zone name that is not the zone configured on your target.

Script Arguments
dns-update.test
Add and remove 4 records to determine if the target is vulnerable.
dns-update.ip
The ip address of the host to add to the zone
dns-update.hostname
The name of the host to add to the zone

Example Usage
nmap -sU -p 53 --script=dns-update --script-args=dns-update.hostname=foo.example.com,dns-update.ip=192.0.2.1 <target>

Default Option Used in script:
nmap  -sU -p 53 --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="53"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sU --script dns-update '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sU --script dns-update  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "17":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-zeustracker

Script types: hostrule
Categories: safe, discovery, external, malware
Download: http://nmap.org/svn/scripts/dns-zeustracker.nse

User Summary
Checks if the target IP range is part of a Zeus botnet by querying ZTDNS @ abuse.ch. Please review the following
information before you start to scan:
https://zeustracker.abuse.ch/ztdns.php

Example Usage
nmap -sn -PN --script=dns-zeustracker <ip>

Default Option Used in script:
nmap  -sn -PN --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sn -PN --script dns-zeustracker'+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn -PN --script dns-zeustracker  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        else:
            os.system('clear')
            print(desc)
            sys.exit(exit_msg)
    elif option == "18":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File dns-zone-transfer

Script types: prerule, portrule
Categories: intrusive, discovery
Download: http://nmap.org/svn/scripts/dns-zone-transfer.nse

User Summary
Requests a zone transfer (AXFR) from a DNS server.
The script sends an AXFR query to a DNS server. The domain to query is determined by examining the name given on the command line, the DNS server's hostname, or it can be specified with the dns-zone-transfer.domain script argument. If the query is successful all domains and domain types are returned along with common type specific data (SOA/MX/NS/PTR/A).
This script can run at different phases of an Nmap scan:
Script Pre-scanning: in this phase the script will run before any
Nmap scan and use the defined DNS server in the arguments. The script arguments in this phase are: dns-zone-transfer.server the DNS server to use, can be a hostname or an IP address and must be specified. The dns-zone-transfer.port argument is optional and can be used to specify the DNS server port.
Script scanning: in this phase the script will run after the other
Nmap phases and against an Nmap discovered DNS server. If we don't have the "true" hostname for the DNS server we cannot determine a likely zone to perform the transfer on.

Useful resources
DNS for rocket scientists: http://www.zytrax.com/books/dns/
How the AXFR protocol works: http://cr.yp.to/djbdns/axfr-notes.html

Script Arguments
dns-zone-transfer.port
DNS server port, this argument concerns the "Script Pre-scanning phase" and it's optional, the default value is 53.
dns-zone-transfer.server
DNS server. If set, this argument will enable the script for the "Script Pre-scanning phase".
newtargets
If specified, adds returned DNS records onto Nmap scanning queue.
dns-zone-transfer.domain
Domain to transfer.
dns-zone-transfer.addall
If specified, adds all IP addresses including private ones onto Nmap scanning queue when the script argument newtargets is given. The default behavior is to skip private IPs (non-routable).
max-newtargets
See the documentation for the target library.

Example Usage
nmap --script dns-zone-transfer.nse \
     --script-args dns-zone-transfer.domain=<domain>


Default Option Used in script:
nmap  -sn -PN --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-no-port[Y/N]:")
        if port_select == "Y" or port_select == "y":
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  -sn -PN --script dns-zone-transfer'+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -sn -PN --script dns-zone-transfer  -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            dns(host_ip,desc)
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