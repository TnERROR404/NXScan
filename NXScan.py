#!/usr/bin/env python
# -*- coding: utf-8 -*-
# NXScan v1.0
# Coded By : NumeX....

import argparse, requests, sys, re, colorama, os
from colorama import *

parser = argparse.ArgumentParser(description="{Fore.YELLOW}[--] NXScan website scanner"+Fore.RESET)
parser.add_argument('-d', required=True, default=None, help='Target Website.')

args = vars(parser.parse_args())

if len(sys.argv) == 1:
    print("{Fore.RED}Usage : python nxscan -d example.com"+Fore.RESET)
    sys.exit()

host = args['d']
if host.startswith('http'):
    sys.exit("\n\n{Fore.YELLOW}[ERROR] Enter domain name\n[EXAMPLE] python nxscan -d example.com"+Fore.RESET)

## ./START Scan common ports ##
def commonPorts():
    os.system('cls')
    requ = requests.post("https://www.portcheckers.com/portscan-result", data={'server': host, "quick": "false"})
    resp = requ.text
    output = re.sub('<pre>|\t|</pre>|<div style="margin:10px 0 20px 0;"><h3>Port Scan Result</h3>|'
                    '<span style="display: inline-block;width:200px;">|</span><span class="label label-danger">|</span>'
                    '|<span class="label label-success">|', '', resp).strip().lstrip()

    output = output.replace("Not Available", " Not Available")
    print("├── Host: 127.0.0.1")
    for lines in str(output).splitlines():
        print("\t├── {}".format(lines))
## ./END Scan common ports ##

## ./START Reverse IP ##
def reverseIP():
    os.system('cls')
    requ = requests.get("https://api.hackertarget.com/reverseiplookup/?q="+host)
    resp = requ.text
    output = resp
    print("├── Host: {}".format(host))
    for lines in str(output).splitlines():
        print("\t├── {}".format(lines))
## ./END Reverse IP ##

## ./START http Header ##
def httpHeader():
    os.system('cls')
    requ = requests.get("https://api.hackertarget.com/httpheaders/?q="+host)
    resp = requ.text
    output = resp.strip().lstrip()
    print("├── Host: {}".format(host))
    for lines in str(output).splitlines():
        print("\t├── {}".format(lines))
## ./END http Header ##

## ./START TCP Port Scan ##
def TCPport():
    os.system('cls')
    requ = requests.get("https://api.hackertarget.com/nmap/?q="+host)
    resp = requ.text
    output = resp.strip().lstrip()
    print("├── Host: {}".format(host))
    for lines in str(output).splitlines():
        print("\t├── {}".format(lines))
## ./END TCP Port Scan ##

## ./START Extract Links from Page ##
def ELFP():
    os.system('cls')
    requ = requests.get("https://api.hackertarget.com/pagelinks/?q="+host)
    resp = requ.text
    output = resp.strip().lstrip()
    print("├── Host: {}".format(host))
    for lines in str(output).splitlines():
        print("\t├── {}".format(lines))
## ./END Extract Links from Page ##

## ./START Extract Links from Page ##
def IPlocation():
    os.system('cls')
    requ = requests.get("https://api.hackertarget.com/geoip/?q="+host)
    resp = requ.text
    output = resp.strip().lstrip()
    print("├── Host: {}".format(host))
    for lines in str(output).splitlines():
        print("\t├── {}".format(lines))

## ./END Extract Links from Page ##

## ./START DNS lookup ##
def DNSlookup():
    os.system('cls')
    requ = requests.get("https://api.hackertarget.com/dnslookup/?q="+host)
    resp = requ.text
    output = re.sub(';; Truncated, retrying in TCP mode.', '', resp).strip().lstrip()
    print("├── Host: {}".format(host))
    for lines in str(output).splitlines():
        print("\t├── {}".format(lines))
## ./END DNS lookup ##

def main():
    os.system('cls')
    print('''
├── Enter Number
\t├──[1] Nmap | TCP Port Scan
\t├──[2] Scan common ports
\t├──[3] Reverse IP
\t├──[4] HTTP Header
\t├──[5] DNS lookup
\t├──[6] IP Location
\t├──[7] Extract Links from Page
\t├──[0] EXIT''')

    chose = int(input('\t├── : '))

    if chose == 1:
        TCPport()
    elif chose == 2:
        commonPorts()
    elif chose == 3:
        reverseIP()
    elif chose == 4:
        httpHeader()
    elif chose == 5:
        DNSlookup()
    elif chose == 6:
        IPlocation()
    elif chose == 7:
        ELFP()
    elif chose == 0:
        sys.exit(0)
    else:
        print("\t{Fore.RED}[-] Incorect"+Fore.RESET)
        main()

    returnChose = str(input("\t└───────[~] Do You Want To Continue? [Y/T] : "))
    if returnChose == 'Y' or returnChose == 'y':
        main()
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()
