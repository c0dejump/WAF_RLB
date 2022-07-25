import requests
import socket
import traceback
from modules.detect_waf import verify_waf
import sys
import pydig

from static.config import PLUS, WARNING, INFO, LESS, LINE, FORBI, SERV_ERR, BYP, WAF, INFO_MOD

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def bypass_by_user_agent(req, res):
    #TODO
    user_agent_list = {
    "Googlebot": ""
    }


def bypass_waf(req, res):
    """
    Bypass_waf: try if the waf can be bypass, using different payloads
    """
    win = False
    domain = res.split("/")[2]
    website_ip = socket.gethostbyname(domain) # take ip website
    dig_ips = pydig.query('tesla.com', 'A')

    header_base = [
    "X-Originating-IP", "X-Forwarded","Forwarded","Forwarded-For","Forwarded-For-IP","X-Forwarder-For","X-Forwarded-For","X-Forwarded-For-Original",
    "X-Forwarded-By","X-Forwarded-Host","X-Remote-IP","X-Remote-Addr","X-Client-IP","Client-IP","Cookie","Access-Control-Allow-Origin","Origin",
    "Timing-Allow-Origin","X-Forwarded-For ", "X-Custom-IP-Authorization", "X-Real-Ip", "X-OReferrer", "X-Forwarded-Server", "Host"
    ]

    options = [website_ip, domain, "127.0.0.1", "127.0.0.2", "*", "8.8.8.8", "null", "192.168.0.2", "10.0.0.1", "localhost", "0.0.0.0","::1","0:0:0:0:0:0:0:1"]

    for i in range(0,255):
        options.append("192.168.0.{}".format(i))
        options.append("10.0.0.{}".format(i))

    for d in dig_ips:
        options.append(d)

    len_list = len(options)*len(header_base)
    l = 0

    for hb in header_base:
        for o in options:
            headers = {
                hb : o
            }
            try:
                display = False
                vrfy = verify_waf(req, res, headers)
                if vrfy == False:
                    win = True
                    for h in headers:
                        print("{}Potential bypass WAF rate limit with option:\033[36m -H \"{}:{}\" \033[0m".format(WAF, h, headers[h]))
                    return headers
            except Exception:
                pass
                traceback.print_exc()
            l += 1
            sys.stdout.write("\033[36m\u251c {}/{} | {}::{}\033[0m\r".format(l, len_list, hb, o))
            sys.stdout.write("\033[K")
    if not win:
        try:
            headers = {
            "Clear-Site-Data":"*"
            }
            display = False
            vrfy = verify_waf(req, res, headers)
            if vrfy == False:
                #win = True
                for h in headers:
                    print("{}Potential bypass WAF rate limit with option:\033[36m -H \"{}:{}\" \033[0m".format(WAF, h, headers[h]))
                return headers
            """else:
                bypass_by_user_agent(req, res)"""
        except:
            pass
            #traceback.print_exc()
    return win

"""if __name__ == '__main__':
    req = "plop"
    user_agent = False
    res = ""
    bypass_waf(req, res)""" #DEBUG