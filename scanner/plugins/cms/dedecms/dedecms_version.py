#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: dedecms版本探测
referer: unknow
author: Lucifer
description: 亿邮邮件系统存在弱口令账户信息泄露，导致非法登录
'''
import re
import sys
import requests



class dedecms_version_BaseVerify:
    def __init__(self, url):
        self.url = url

    def check_ver(self, arg):
        ver_histroy = {'20080307': 'v3 or v4 or v5',
                 '20080324': 'v5 above',
                 '20080807': '5.1 or 5.2',
                 '20081009': 'v5.1sp',
                 '20081218': '5.1sp',
                 '20090810': '5.5',
                 '20090912': '5.5',
                 '20100803': '5.6',
                 '20101021': '5.3',
                 '20111111': 'v5.7 or v5.6 or v5.5',
                 '20111205': '5.7.18',
                 '20111209': '5.6',
                 '20120430': '5.7SP or 5.7 or 5.6',
                 '20120621': '5.7SP1 or 5.7 or 5.6',
                 '20120709': '5.6',
                 '20121030': '5.7SP1 or 5.7',
                 '20121107': '5.7',
                 '20130608': 'V5.6-Final',
                 '20130922': 'V5.7SP1'}
        ver_list = sorted(list(ver_histroy.keys()))
        ver_list.append(arg)
        sorted_ver_list=sorted(ver_list)
        return ver_histroy[ver_list[sorted_ver_list.index(arg) - 1]]

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/data/admin/ver.txt"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            m = re.search("^(\d+)$", req.text)
            if m:
                return "[+]探测到dedecms版本...(敏感信息)\t时间戳: %s, 版本信息: %s"%(m.group(1), self.check_ver(m.group(1)))

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = dedecms_version_BaseVerify(sys.argv[1])
    testVuln.run()