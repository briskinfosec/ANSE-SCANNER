 #!/usr/bin/env python3
import subprocess
from socket import *
import os.path
import sys
import argparse
from banner import xe_header
dir = '/usr/bin/nmap'
exit_msg ="\n[++] You Enter wrong detail or You Entered Exit ... Goodbye.\n"
def nmap_package(path):
    if os.path.exists(path):
        print("Nmap  is already installed")
    else:
        subprocess.call('sudo apt-get install nmap',shell=True)
        os.system('clear')
        print("Now Nmap is installed")
def ANSE_help(host_ip,desc):
    os.system('clear')
    print(desc)
    print("""\033[92m\033[1m
                                                     ANSE SCANNER  KEYWORD HELP
                                    +--------------------------+---------------------------------+
                                    |   HOST ADDRESS           | Set Host Address for  ANSE      |
                                    +--------------------------+---------------------------------+
                                    |  SERVICE  NSE SCRIPT     | Select NSE script for Service   |
                                    |                          |                                 |
                                    |                          |  -Y/y-Set Default Port Option   |
                                    |  +Y/N/NILL (or) y/n/nill |  -N/n-Custom Port option        |
                                    |                          |  -Nil/nil-No port Specified     |
                                    +--------------------------+---------------------------------+
                                    |  SCRIPT UPDATE           |  Updating ANSE script with NMAP |
                                    +--------------------------+---------------------------------+
                                    |  NMAP HELP               |  Nmap Help Sheet                |
                                    +--------------------------+---------------------------------+
                                \033[0m'""")
    input("Press Enter to Continue")
    index_scan(host_ip,desc)


def script_update(host_ip,desc):
    os.system('clear')
    subprocess.call('nmap --script-updatedb',shell=True)
    index_scan(host_ip,desc)
def service_scan(host_ip,desc):
    #print(desc)
    print("""\033[92m\033[1m
+----------------------------------------------------------------------------------------=---------+
|  +Choose your Service Type                                                                       |
|-------------------+------------------+------------------+--------------------+-------------------|
| [01] acarsd       | [36] epmd        | [71] llmnr       | [106] openlookup   | [141] snmp        |
| [02] address      | [37] eppc        | [72] lltd        | [107] openvas      | [142] socks       |
| [03] afp          | [38] fcrdns      | [73] maxdb       | [108] oracle       | [143] ssh         |
| [04] ajp          | [39] finger      | [74] mcafee      | [109] p2p          | [144] ssl         |
| [05] amqp         | [40] firewall    | [75] membase     | [110] pc           | [145] sstp        |
| [06] asn          | [41] fox         | [76] memcached   | [111] pgsql        | [146] stun        |
| [07] ataoe        | [42] freelancer  | [77] metasploit  | [112] pjl          | [147] stuxnet     |
| [08] auth         | [43] ftp         | [78] mikrotik    | [113] plc          | [148] supermicro  |
| [09] backorifice  | [44] game_script | [79] mmouse      | [114] pop3         | [149] svn         |
| [10] bacnet       | [45] ganglia     | [80] modbus      | [115] pptp         | [150] targets     |
| [11] banner       | [46] giop        | [81] mongodb     | [116] qconn        | [151] teamspeak2  |
| [12] bitcoin      | [47] gkrellm     | [82] mqtt        | [117] qscan        | [152] telnet      |
| [13] bjnp         | [48] gopher      | [83] mrinfo      | [118] quake        | [153] tftp        |
| [14] Cassandra_db | [49] gpsd        | [84] msrpc       | [119] rdp          | [154] time        |
| [15] cccam        | [50] hadoop      | [85] ms-sql      | [120] realvnc      | [155] tls         |
| [16] citrix       | [51] hbase       | [86] mtrace      | [121] redis        | [156] tor         |
| [17] clamav       | [52] hddtemp     | [87] mtu         | [122] resolve      | [157] traceroute  |
| [18] clock        | [53] hnap        | [88] multihomed  | [123] reverse      | [158] unittest    |
| [19] coap         | [54] http        | [89] murmur      | [124] rexec        | [159] unusual     |
| [20] couchdb      | [55] iax2        | [90] mysql       | [125] riak         | [160] upnp        |
| [21] creds        | [56] ibmdb2      | [91] nat         | [126] rlogin       | [161] url         |
| [22] cups         | [57] icap        | [92] nbstat      | [127] rmi          | [162] ventrilo    |
| [23] cvs          | [58] ike         | [93] ncp         | [128] rpcap        | [163] versant     |
| [24] daap         | [59] imap        | [94] ndmp        | [129] rpc          | [164] vmauthd     |
| [25] daytime      | [60] informix    | [95] nessus      | [130] rsync        | [165] vnc         |
| [26] dhcp         | [61] ipmi        | [96] netbus      | [131] rtsp         | [166] voldemort   |
| [27] dict         | [62] ip          | [97] nexpose     | [132] rusers       | [167] vuze        |
| [28] distcc       | [63] ipv6        | [98] nfs         | [133] samba        | [168] wdb         |
| [29] dns          | [64] irc         | [99] nje         | [134] servicetags  | [169] weblogic    |
| [30] docker       | [65] iscsi       |[100] nntp        | [135] shodan       | [170] whois       |
| [31] domcon       | [66] jdwp        |[101] nping       | [136] sip          | [171] wsdd        |
| [32] dpap         | [67] knx         |[102] nrpe        | [137] skype        | [172] x11         |
| [33] drda         | [68] krb5        |[103] ntp         | [138] smb          | [174] xmlrpc      |
| [34] eap          | [69] ldap        |[104] omp2        | [139] smtp         | [174] xmpp        |
| [35] enip         | [70] lexmark     |[105] omron       | [140] sniffer      |  [0]  back        |
+-------------------+------------------+------------------+--------------------+-------------------+\033[0m""")
    service_type=input("Enter your Service no[int]:")
    if service_type == "1":
        from lib.acarsd import acarsd
        acarsd(host_ip,desc)
    elif service_type == "2":
        from lib.address import address
        address(host_ip,desc)
    elif service_type == "3":
        from lib.afp import afp
        afp(host_ip,desc)
    elif service_type == "4":
        from lib.ajp import ajp
        ajp(host_ip,desc)
    elif service_type == "5":
        from lib.amqp import amqp
        amqp(host_ip,desc)
    elif service_type == "6":
        from lib.asn import asn
        asn(host_ip,desc)
    elif service_type == "7":
        from lib.ataoe import ataoe
        ataoe(host_ip,desc)
    elif service_type == "8":
        from lib.auth import auth
        auth(host_ip,desc)
    elif service_type == "9":
        from lib.backorifice import backorifice
        backorifice(host_ip,desc)
    elif service_type == "10":
        from lib.bacnet import bacnet
        bacnet(host_ip,desc)
    elif service_type == "11":
        from lib.banner import banner
        banner(host_ip,desc)
    elif service_type == "12":
        from lib.bitcoin import bitcoin
        bitcoin(host_ip,desc)
    elif service_type == "13":
        from lib.bjnp import bjnp
        bjnp(host_ip,desc)
    elif service_type == "14":
        from lib.Cassandra_db import cassandra_db
        cassandra_db(host_ip,desc)
    elif service_type == "15":
        from lib.cccam import cccam
        cccam(host_ip,desc)
    elif service_type == "16":
        from lib.citrix import citrix
        citrix(host_ip,desc)
    elif service_type == "17":
        from lib.clamav import clamav
        clamav(host_ip,desc)
    elif service_type == "18":
        from lib.clock import clock
        clock(host_ip,desc)
    elif service_type == "19":
        from lib.coap import coap
        coap(host_ip,desc)
    elif service_type == "20":
        from lib.couchdb import couchdb
        couchdb(host_ip,desc)
    elif service_type =="21":
        from lib.creds import creds
        creds(host_ip,desc)
    elif service_type == "22":
        from lib.cups import cups
        cups(host_ip,desc)
    elif service_type == "23":
        from lib.cvs import cvs
        cvs(host_ip,desc)
    elif service_type == "24":
        from lib.daap import daap
        daap(host_ip,desc)
    elif service_type == "25":
        from lib.daytime import daytime
        daytime(host_ip,desc)
    elif service_type == "26":
        from lib.dhcp import dhcp
        dhcp(host_ip,desc)
    elif service_type == "27":
        from lib.dict import dict
        dict(host_ip,desc)
    elif service_type == "28":
        from lib.distcc import distcc
        distcc(host_ip,desc)
    elif service_type == "29":
        from lib.dns import dns
        dns(host_ip,desc)
    elif service_type == "30":
        from lib.docker import docker
        docker(host_ip,desc)
    elif service_type == "31":
        from lib.domcon import domcon
        domcon(host_ip,desc)
    elif service_type == "32":
        from lib.dpap import dpap
        dpap(host_ip,desc)
    elif service_type == "33":
        from lib.drda import drda
        drda(host_ip,desc)
    elif service_type == "34":
        from lib.eap import eap
        eap(host_ip,desc)
    elif service_type == "35":
        from lib.enip import enip
        enip(host_ip,desc)
    elif service_type == "36":
        from lib.epmd import epmd
        epmd(host_ip,desc)
    elif service_type == "37":
        from lib.eppc import eppc
        eppc(host_ip,desc)
    elif service_type == "38":
        from lib.fcrdns import fcrdns
        fcrdns(host_ip,desc)
    elif service_type == "39":
        from lib.finger import finger
        finger(host_ip,desc)
    elif service_type == "40":
        from lib.firewall import firewall
        firewall(host_ip,desc)
    elif service_type == "41":
        from lib.fox import fox
        fox(host_ip,desc)
    elif service_type == "42":
        from lib.freelancer import freelacer
        freelacer(host_ip,desc)
    elif service_type == "43":
        from lib.ftp import ftp
        ftp(host_ip,desc)
    elif service_type == "44":
        from lib.game_script import game_server
        game_server(host_ip,desc)
    elif service_type == "45":
        from lib.ganglia import ganglia
        ganglia(host_ip,desc)
    elif service_type == "46":
        from lib.giop import giop
        giop(host_ip,desc)
    elif service_type == "47":
        from lib.gkrellm import gkrellm
        gkrellm(host_ip,desc)
    elif service_type == "48":
        from lib.gopher import gopher
        gopher(host_ip,desc)
    elif service_type == "49":
        from lib.gpsd import gpsd
        gpsd(host_ip,desc)
    elif service_type == "50":
        from lib.hadoop import hadoop
        hadoop(host_ip,desc)
    elif service_type == "51":
        from lib.hbase import hbase
        hbase(host_ip,desc)
    elif service_type == "52":
        from lib.hddtemp import hddtemp
        hddtemp(host_ip,desc)
    elif service_type == "53":
        from lib.hnap import hnap
        hnap(host_ip,desc)
    elif service_type == "54":
        from lib.http import http
        http(host_ip,desc)
    elif service_type == "55":
        from lib.iax2 import  iax2
        iax2(host_ip,desc)
    elif service_type == "56":
        from lib.ibmdb2 import IBMDB2
        IBMDB2(host_ip,desc)
    elif service_type == "57":
        from lib.icap import icap
        icap(host_ip,desc)
    elif service_type == "58":
        from lib.ike import ike
        ike(host_ip,desc)
    elif service_type == "59":
        from lib.imap import imap
        imap(host_ip,desc)
    elif service_type == "60":
        from.lib.informix import informix
        informix(host_ip,desc)
    elif service_type == "61":
        from lib.ipmi import ipmi
        ipmi(host_ip,desc)
    elif service_type == "62":
        from lib.ip import ip
        ip(host_ip,desc)
    elif service_type == "63":
        from lib.ipv6 import ipv6
        ipv6(host_ip,desc)
    elif service_type == "64":
        from lib.irc import irc
        irc(host_ip,desc)
    elif service_type == "65":
        from lib.iscsi import iscsi
        iscsi(host_ip,desc)
    elif service_type == "66":
        from lib.jdwp import jdwp
        jdwp(host_ip,desc)
    elif service_type == "67":
        from lib.knx import knx
        knx(host_ip,desc)
    elif service_type == "68":
        from lib.krb5 import  krb5
        krb5(host_ip,desc)
    elif service_type == "69":
        from lib.ldap import ldap
        ldap(host_ip,desc)
    elif service_type == "70":
        from lib.lexmark import lexmark
        lexmark(host_ip,desc)
    elif service_type == "71":
        from lib.llmnr import llmnr
        llmnr(host_ip,desc)
    elif service_type =="72":
        from lib.lltd import lltd
        lltd(host_ip,desc)
    elif service_type == "73":
        from lib.maxdb import maxdb
        maxdb(host_ip,desc)
    elif service_type == "74":
        from lib.mcafee import mcafee
        mcafee(host_ip,desc)
    elif service_type == "75":
        from lib.membase import membase
        membase(host_ip,desc)
    elif service_type == "76":
        from lib.memcached import memcached
        memcached(host_ip,desc)
    elif service_type == "77":
        from lib.metasploit import metasploit
        metasploit(host_ip,desc)
    elif service_type == "78":
        from lib.mikrotik import mikrotik
        mikrotik(host_ip,desc)
    elif service_type =="79":
        from lib.mmouse import mmouse
        mmouse(host_ip,desc)
    elif service_type == "80":
        from lib.modbus import modbus
        modbus(host_ip,desc)
    elif service_type == "81":
        from lib.mongodb import mongodb
        mongodb(host_ip,desc)
    elif service_type == "82":
        from lib.mqtt import mqtt
        mqtt(host_ip,desc)
    elif service_type =="83":
        from lib.mrinfo import mrinfo
        mrinfo(host_ip,desc)
    elif service_type == "84":
        from lib.msrpc import msrpc
        msrpc(host_ip,desc)
    elif service_type == "85":
        from lib.mssql import mssql
        mssql(host_ip,desc)
    elif service_type == "86":
        from lib.mtrace import mtrace
        mtrace(host_ip,desc)
    elif service_type == "87":
        from lib.mtu import mtu
        mtu(host_ip,desc)
    elif service_type == "88":
        from lib.multihomed import multihomed
        multihomed(host_ip,desc)
    elif service_type =="89":
        from lib.murmur import murmur
        murmur(host_ip,desc)
    elif service_type == "90":
        from lib.mysql import mysql
        mysql(host_ip,desc)
    elif service_type == "91":
        from lib.nat import nat
        nat(host_ip,desc)
    elif service_type == "92":
        from lib.nbstat import nbstat
        nbstat(host_ip,desc)
    elif service_type =="93":
        from lib.ncp import ncp
        ncp(host_ip,desc)
    elif service_type =="94":
        from lib.ndmp import ndmp
        ndmp(host_ip,desc)
    elif service_type == "95":
        from lib.nessus import nessus
        nessus(host_ip,desc)
    elif service_type == "96":
        from lib.netbus import netbus
        netbus(host_ip,desc)
    elif service_type =="97":
        from lib.nexpose import nexpose
        nexpose(host_ip,desc)
    elif service_type == "98":
        from lib.nfs import nfs
        nfs(host_ip,desc)
    elif service_type == "99":
        from lib.nje import nje
        nje(host_ip,desc)
    elif service_type == "100":
        from lib.nntp import nntp
        nntp(host_ip,desc)
    elif service_type == "101":
        from lib.nping import nping
        nping(host_ip,desc)
    elif service_type == "102":
        from lib.nrpe import nrpe
        nrpe(host_ip,desc)
    elif service_type == "103":
        from lib.ntp import ntp
        ntp(host_ip,desc)
    elif service_type == "104":
        from lib.omp2 import omp2
        omp2(host_ip,desc)
    elif service_type =="105":
        from lib.omron import omron
        omron(host_ip,desc)
    elif service_type == "106":
        from lib.openlookup import openlookup
        openlookup(host_ip,desc)
    elif service_type == "107":
        from lib.openvas import openvas
        openvas(host_ip,desc)
    elif service_type == "108":
        from lib.oracle import oracle
        oracle(host_ip,desc)
    elif service_type == "109":
        from lib.p2p import p2p
        p2p(host_ip,desc)
    elif service_type == "110":
        from lib.pc import pc
        pc(host_ip,desc)
    elif service_type == "111":
        from lib.pgsql import pgsql
        pgsql(host_ip,desc)
    elif service_type == "112":
        from lib.pjl import pjl
        pjl(host_ip,desc)
    elif service_type == "113":
        from lib.plc import plc
        plc(host_ip,desc)
    elif service_type == "114":
        from lib.pop3 import pop3
        pop3(host_ip,desc)
    elif service_type == "115":
        from lib.pptp import pptp
        pptp(host_ip,desc)
    elif service_type == "116":
        from lib.qconn import qconn
        qconn(host_ip,desc)
    elif service_type == "117":
        from lib.qscan import qscan
        qscan(host_ip,desc)
    elif service_type == "118":
        from lib.quake import quake
        quake(host_ip,desc)
    elif service_type == "119":
        from lib.rdp import rdp
        rdp(host_ip,desc)
    elif service_type =="120":
        from lib.realvnc import realvnc
        realvnc(host_ip,desc)
    elif service_type == "121":
        from lib.redis import redis
        redis(host_ip,desc)
    elif service_type == "122":
        from lib.resolve import resolve
        resolve(host_ip,desc)
    elif service_type == "123":
        from lib.reverse import reverse
        reverse(host_ip,desc)
    elif service_type == "124":
        from lib.rexec import rexec
        rexec(host_ip,desc)
    elif service_type == "125":
        from lib.riak import riak
        riak(host_ip,desc)
    elif service_type == "126":
        from lib.rlogin import rlogin
        rlogin(host_ip,desc)
    elif service_type == "127":
        from lib.rmi import rmi
        rmi(host_ip,desc)
    elif service_type == "128":
        from lib.rpcap import rpcap
        rpcap(host_ip,desc)
    elif service_type == "129":
        from lib.rpc import rpc
        rpc(host_ip,desc)
    elif service_type == "130":
        from lib.rsync import rsync
        rsync(host_ip,desc)
    elif service_type == "131":
        from lib.rtsp import rtsp
        rtsp(host_ip,desc)
    elif service_type == "132":
        from lib.rusers import rusers
        rusers(host_ip,desc)
    elif service_type == "133":
        from lib.samba import samba
        samba(host_ip,desc)
    elif service_type == "134":
        from lib.servicetags import servicetags
        servicetags(host_ip,desc)
    elif service_type == "135":
        from lib.shodan import shodan
        shodan(host_ip,desc)
    elif service_type == "136":
        from lib.sip import sip
        sip(host_ip,desc)
    elif service_type == "137":
        from lib.skype import skype
        skype(host_ip,desc)
    elif service_type == "138":
        from lib.smb import smb
        smb(host_ip,desc)
    elif service_type == "139":
        from lib.smtp import smtp
        smtp(host_ip,desc)
    elif service_type  == "140":
        from lib.sniffer import sniffer
        sniffer(host_ip,desc)
    elif service_type == "141":
        from lib.snmp import snmp
        snmp(host_ip,desc)
    elif service_type == "142":
        from lib.socks import socks
        socks(host_ip,desc)
    elif service_type =="143":
        from lib.ssh import ssh
        ssh(host_ip,desc)
    elif service_type == "144":
        from lib.ssl import ssl
        ssl(host_ip,desc)
    elif service_type == "145":
        from lib.sstp import sstp
        sstp(host_ip,desc)
    elif service_type == "146":
        from lib.stun import stun
        stun(host_ip,desc)
    elif service_type == "147":
        from lib.stuxnet import stuxnet
        stuxnet(host_ip,desc)
    elif service_type == "148":
        from lib.supermicro import supermicro
        supermicro(host_ip,desc)
    elif service_type == "149":
        from lib.svn import svn
        svn(host_ip,desc)
    elif service_type == "150":
        from lib.targets import targets
        targets(host_ip,desc)
    elif service_type == "151":
        from lib.teamspeak2 import teamspeak2
        teamspeak2(host_ip,desc)
    elif service_type == "152":
        from lib.telnet import telnet
        telnet(host_ip,desc)
    elif service_type == "153":
        from lib.tftp import tftp
        tftp(host_ip,desc)
    elif service_type == "154":
        from lib.time import time
        time(host_ip,desc)
    elif service_type == "155":
        from lib.tls import tls
        tls(host_ip,desc)
    elif service_type == "156":
        from lib.tor import tor
        tor(host_ip,desc)
    elif service_type =="157":
        from lib.traceroute import traceroute
        traceroute(host_ip,desc)
    elif service_type == "158":
        from lib.unittest import unittest
        unittest(host_ip,desc)
    elif service_type == "159":
        from lib.unusual import unusual
        unusual(host_ip,desc)
    elif service_type == "160":
        from lib.upnp import upnp
        upnp(host_ip,desc)
    elif service_type =="161":
        from lib.url import url
        url(host_ip,desc)
    elif service_type == "162":
        from lib.ventrilo import ventrilo
        ventrilo(host_ip,desc)
    elif service_type == "163":
        from lib.versant import versant
        versant(host_ip,desc)
    elif service_type == "164":
        from lib.vmauthd import vmauthd
        vmauthd(host_ip,desc)
    elif service_type == "165":
        from lib.vnc import vnc
        vnc(host_ip,desc)
    elif service_type == "166":
        from lib.voldemort import voldemort
        voldemort(host_ip,desc)
    elif service_type == "167":
        from lib.vuze import vuze
        vuze(host_ip,desc)
    elif service_type == "168":
        from lib.wdb import wdb
        wdb(host_ip,desc)
    elif service_type == "169":
        from lib.weblogic import weblogic
        weblogic(host_ip,desc)
    elif service_type == "170":
        from lib.whois import whois
        whois(host_ip,desc)
    elif service_type == "171":
        from.lib.wsdd import wsdd
        wsdd(host_ip,desc)
    elif service_type == "172":
        from lib.x11 import x11
        x11(host_ip,desc)
    elif service_type =="173":
        from lib.xmlrpc import xmlrpc
        xmlrpc(host_ip,desc)
    elif service_type == "174":
        from lib.xmpp import xmpp
        xmpp(host_ip,desc)
    elif service_type == "0":
        index_scan(host_ip,desc)
    else:
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)
def index_scan(host_ip,desc):
    os.system('clear')
    print(desc)
    print("""\033[95m
     Your Target Host Address:"""+host_ip
     +"""\033[95m
     +Choose your option for ANSE Scanner:
        [1] SERVICE NSE SCRIPT
        [2] SCRIPT-UPDATE
        [3] NMAP HELP
        [4] ANSE HELP
        [5] EXIT
     \033[0m""")

    cmd=input("Enter you Option no[INT]:")
    os.system('clear')
    if cmd == "1":
        service_scan(host_ip,desc)
    elif cmd == "2":
        script_update(host_ip,desc)
    elif cmd == "3":
        subprocess.call('nmap --help', shell=True)
        input("\033[94mPress enter to continue\033[0m")
        index_scan(host_ip, desc)
    elif cmd == "4":
        ANSE_help(host_ip,desc)
    else:
        os.system('clear')
        print(desc)
        sys.exit(exit_msg)
if __name__ == '__main__':
    os.system('clear')
    #def host():
    line = "=" * 150
    banner=xe_header()
    desc = "\033[37m" +  line +"\033[0m"+"\n" +banner+"\n"+ "\033[37m" + line +" \033[0m" +"\n"
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawTextHelpFormatter)
    args = parser.parse_args()
    #host_ip = input("Enter you Host IP:")
    print(desc)
    nmap_package(dir)
    host_ip = input("Enter you Host IP:")
    # host_addr=gethostbyaddr(host_ip)
    index_scan(host_ip,desc)
