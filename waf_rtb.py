#! /usr/bin/env python3
# -*- coding: utf-8 -*-

#modules in standard library
import requests
from requests.exceptions import Timeout
import sys, os, re
import time
from datetime import datetime
from time import strftime
import argparse
import traceback
import random
import string
import multiprocessing

from modules.detect_waf import detect_wafw00f
from modules.detect_waf import verify_waf
from modules.bypass_waf import bypass_waf
from static.banner import banner

from static.config import PLUS, WARNING, INFO, LESS, LINE, FORBI, SERV_ERR, BYP, WAF, INFO_MOD

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def create_structure_scan(url):
    #Just to save WAF result
    url = url if len(url.split('/')) == 4 else '/'.join(url.split('/')[:-2]) + '/'

    now = datetime.now()
    today = now.strftime("_%Y-%m-%d")

    today_hour = now.strftime("_%Y-%m-%d_%H-%M")

    dire = ''
    found_dire = False

    if 'www' in url:
        direct = url.split('.')
        director = direct[1]
        dire = "{}.{}".format(direct[1], direct[2].replace("/",""))
        directory = "sites/{}".format(dire)
    else:
        direct = url.split('/')
        director = direct[2]
        dire = director
        directory = "sites/" + dire

    listdir = os.listdir("sites/")
    for ld in listdir:
        if dire in ld:
            found_dire = True

    if not found_dire:
        os.makedirs(directory)
        dw = detect_wafw00f(url, directory)
    else:
        dire_date = "sites/{}{}".format(dire, today_hour)
        os.makedirs(dire_date) 
        dw = detect_wafw00f(url, dire_date)


def requests_url(s, url):
    #URL with random char BF
    try:
        req = s.get(url, verify=False, timeout=10)
        return req
    except Timeout:
        rt_error += 1
    except:
        pass
    #print(req)


def while_requests(url):

    global rt_error
    rt_error = 0


    s = requests.session()

    url_rand = "{}{}".format(url, ''.join(random.choice(string.ascii_letters) for x in range(5)))

    req = s.get(url, verify=False, timeout=10)

    while req.status_code in [200, 404, 302, 301]:
        processes = []
     
        # Creates 50 processes
        for i in range(30):
            p = multiprocessing.Process(target=requests_url, args=(s, url_rand))
            p.start()
            processes.append(p)
        
        # Joins all the processes 
        for p in processes:
             p.join()

        try:
            req = s.get(url, verify=False, timeout=10)
            print(req)
        except:
            pass

        if rt_error > 30:
            print(" {} Website not accessible".format(WARNING))
            sys.exit()
    if req.status_code not in [200, 404, 302, 301] and req.status_code != 429:
        #Verify false positive and if it's a known waf page
        vw = verify_waf(s, url_rand)
        if vw == None or vw == True:
            print("{}Start of bypass tests".format(INFO_MOD))
            bypass_waf(s, url)
    elif req.status_code == 429 and "CAPTCHA" in req.text:
        print("{}{}{} Seems to be a captcha...".format(INFO_MOD, WAF, req.status_code))
        sys.exit()




if __name__ == '__main__':
    #arguments
    parser = argparse.ArgumentParser(add_help = True)
    parser = argparse.ArgumentParser(description='\033[32mVersion ß | contact: https://twitter.com/c0dejump\033[0m')
    
    parser.add_argument("-u", help="URL to scan \033[31m[required]\033[0m", dest='url')

    results = parser.parse_args()

    url = results.url

    banner()
    
    create_structure_scan(url)
    while_requests(url)

