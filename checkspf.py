#!/usr/bin/env python3

import sys
import os
import re
import spf
import ipaddress

list_of_networks = [
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv4Network("127.0.0.1/32"),
]
# for domains with broken spf but we still want to receive mails
domain_whitelist = [
    'agence.generali.fr',
]

def recv(stdin):
    return stdin.readline().rstrip('\r\n')

def send(stdout, line):
    print(line, file=stdout)

if __name__ == "__main__":
    _stdin  = os.fdopen(sys.stdin.fileno(),  'r', encoding='latin-1', buffering=1)
    _stdout = os.fdopen(sys.stdout.fileno(), 'w', encoding='latin-1', buffering=1)
    #_stderr = os.fdopen(sys.stderr.fileno(), 'w', encoding='latin-1', buffering=1)

    while recv(_stdin) != 'config|ready':
        pass

    send(_stdout, "register|report|smtp-in|link-connect")
    send(_stdout, "register|report|smtp-in|link-identify")
    send(_stdout, "register|report|smtp-in|link-disconnect")
    send(_stdout, "register|filter|smtp-in|mail-from")
    send(_stdout, "register|ready")

    tuple_connection = {}

    while True:
        line = recv(_stdin)
        
        if line.count("|") == 0:
            continue

        split_strings = line.split("|")
        phase = split_strings[4]

        if phase == "link-connect":
            *stuff, sessionid, rdns, fcrdns, src, dest = line.split("|")
            ipsrc = re.match(r'^(.*?)(:\d+)?$', src).group(1).strip("[]")  #on extrait ip sans le port
            tuple_connection.update({sessionid: [ipsrc]})

        if phase == "link-identify":
            *stuff, sessionid, method, identity = line.split("|")
            tuple_connection[sessionid].append(identity) 

        if phase == "mail-from":
            *stuff, sessionid, token, mailfrom = line.split("|")
            ipsrc, identity = tuple_connection[sessionid][:2]
            #we check if whitelisted
            ip_to_check = ipaddress.ip_address(ipsrc)
            domain = mailfrom.split('@')[1] 
            is_ip_whitelisted = any(ip_to_check in network for network in list_of_networks)
            is_domain_whitelisted = domain in domain_whitelist
            if is_ip_whitelisted or is_domain_whitelisted:
                send(_stdout, f"filter-result|{sessionid}|{token}|proceed")
            else:
                result = spf.check2(i=ipsrc, s=mailfrom, h=identity)
                if result[0] == "pass" or result[0] == "none" or result[0] == "neutral":
                    send(_stdout, f"filter-result|{sessionid}|{token}|proceed")
                elif result[0] == "fail" or result[0] == "permerror":
                    send(_stdout, f"filter-result|{sessionid}|{token}|reject|550 5.7.1 SPF check failed")
                elif result[0]  == "temperror":
                    send(_stdout, f"filter-result|{sessionid}|{token}|reject|451 4.4.3 SPF check failed")
                elif result[0] == "softfail" :
                    send(_stdout, f"filter-result|{sessionid}|{token}|junk")
                else:
                    send(_stdout, f"filter-result|{sessionid}|{token}|junk")
                
        if phase == "link-disconnect":
            *stuff, sessionid = line.split("|")
            tuple_connection.pop(sessionid,None)  #we clear the entry
