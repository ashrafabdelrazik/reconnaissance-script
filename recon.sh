#!/bin/bash

t=$1

# Enumerating Subdomains
sublist3r -d $t -o subdomains.txt
subfinder -d $t -all | anew subdomains.txt
amass enum -passive -config ~/.config/recon/config.ini -d $1 | anew subdomains.txt
assetfinder --subs-only $t | anew subdomains.txt

# Check Subdomains(different ports)
cat subdomains.txt | httpx -title -wc -sc -cl -ct -web-server -asn -o httpx-out.txt -p 8000,8080,8443,443,80,8008,3000,5000,9090,900,7070,9200,15672,9000 -threads 75 -location
cat httpx-out.txt | cut -d " " -f1 | awk -F '://' '!seen[$2]++' | sort -u | uniq | anew alive-subdomains.txt

# URLS & Leaks (waymore)
mkdir -p waymore-out
for i in $(cat alive-subdomains.txt)
do
  waymore -mode U -xwm -xcc -xus -i $i -c ~/.config/recon/config.yml -oU waymore-out/$RANDOM
done

# Find creds in waymore fetches
cat waymore-out/* | grep -i "key=\|api=\|htm:\|aspx:\|in:\|up:\|register:\|\/:\|gmail.com:\|[(a-zA-Z0-9)]@[(a-zA-Z0-9)].[(a-zA-Z0-9)]:" | anew waymore-creds

# Directory Fuzzing (ffuf)
mkdir -p ffuf-out
for i in $(cat alive-subdomains.txt); do ffuf -c -r -w ~/.config/recon/wordlist.txt -u $i/FUZZ -mc 200 -of html -o ffuf-out/$RANDOM ; done

# Peak (PUT Method)
for i in $(cat hosts); do curl -X 'PUT' --data-binary 'h1ashtestputmethod' '$i/h1ashup.html' ; done
cat alive-subdomains.txt | sed 's/$/\/h1ashup.html/g' | fff -d 1 -S -o fff-out

## Peak (.git)
for i in $(cat alive-subdomains.txt); do goop $i; done

# censys.io
# urlscan.io
# Subdomain Takeover
