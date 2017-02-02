def mqtt(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for mqtt:
      [1] mqtt-subscribe
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File mqtt-subscribe

Script types: portrule
Categories: safe, discovery, version
Download: http://nmap.org/svn/scripts/mqtt-subscribe.nse

User Summary
Dumps message traffic from MQTT brokers.
This script establishes a connection to an MQTT broker and subscribes to the requested topics. The default topics have been
chosen to receive system information and all messages from other clients. This allows Nmap, to listen to all messages being
published by clients to the MQTT broker.

For additional information:
    https://en.wikipedia.org/wiki/MQTT
    https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html

Script Arguments
mqtt-subscribe.protocol-name
MQTT protocol name, defaults to MQTT.
mqtt-subscribe.listen-msgs
Number of PUBLISH messages to receive, defaults to 100. A value of zero forces this script to stop only when listen-time has passed.
mqtt-subscribe.username
Username for MQTT brokers requiring authentication.
mqtt-subscribe.protocol-level
MQTT protocol level, defaults to 4.
mqtt-subscribe.topic
Topic filters to indicate which PUBLISH messages we'd like to receive.
mqtt-subscribe.password
Password for MQTT brokers requiring authentication.
mqtt-subscribe.listen-time
Length of time to listen for PUBLISH messages, defaults to 5s. A value of zero forces this script to stop only when listen-msgs PUBLISH messages have been received.
mqtt-subscribe.client-id
MQTT client identifier, defaults to nmap with a random suffix.

Example Usage
nmap -p 1883 --script mqtt-subscribe <target>

Default Option Used in script:
nmap  -p  1883  --script [script name]  [arg] [host_ip] -oN [file_name]\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default option-port-1883[Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="1883"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mqtt-subscribe -p '+' '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mqtt(host_ip,desc)
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap  --script mqtt-subscribe -p '+' '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            mqtt(host_ip,desc)
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