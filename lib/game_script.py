def game_server(host_ip,desc):
    import sys
    import os
    import subprocess
    from ANSE import exit_msg
    desc = desc
    host_ip = host_ip
    os.system('clear')
    print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
 +Choose  your NSE script for All-Seeing Eye service (game_Server)
      [1] allseeingeye-info
      [0] back\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
    option=input("Enter your NSE script no:")
    os.system('clear')
    if option == "1":
        print("""\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m\033[94m
File allseeingeye-info

Script types: portrule
Categories: discovery, safe, version
Download: http://nmap.org/svn/scripts/allseeingeye-info.nse

User Summary
Detects the All-Seeing Eye service. Provided by some game servers for querying the server's status.
The All-Seeing Eye service can listen on a UDP port separate from the main game server port (usually game port+123). 
On receiving a packet with the payload "s", it replies with various game server status info.
When run as a version detection script (-sV), the script will report on the game name, version, actual port, and
whether it has a password. 
When run explicitly (--script ase-info), the script will additionally report on the server name, game type, map name,
current number of players, maximum number of players, player information, and various other information.

Example Usage
nmap -sV <target>
nmap -Pn -sU -sV --script allseeingeye-info -p <port> <target>\033[0m\033[37m
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\033[0m""")
        port_select=input("Set Default port-27138 [Y/N]:")
        if port_select == "Y" or port_select == "y":
            default_port="27138"
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap -Pn -sU -sV --script allseeingeye-info -p '+default_port+' '+arg+' '+host_ip+' '+output,shell=True)
            game_server(host_ip,desc)      
        elif port_select == "N" or port_select == "n":
            custom_port=input("Enter your Custom port:")
            arg=input("Enter argument if you need or press just enter:")
            file_name=input("Enter your file name to save:")
            output="-oN"+' '+"output/"+host_ip+"-"+file_name+".txt"
            subprocess.call('nmap --script afp-brute  -p '+custom_port+' '+arg+' '+host_ip+' '+output,shell=True)
            game_server(host_ip,desc)      
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
