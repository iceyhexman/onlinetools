#coding=utf-8
import requests
import json
import time
import zlib


class gwhatweb:
    def __init__(self,url):
        self.url = url
        self.time=0

    def whatweb(self):
        start = time.clock()
        contentraw=self.getresult(self.url)
        count=contentraw.headers["X-RateLimit-Remaining"]
        content=contentraw.json()
        end = time.clock()
        self.time = end - start
        if content['CMS']:
            try:
                return {'total':count,'url':self.url,'result':"CMS: "+content['CMS'][0]+",Programming Languages:"+content['Programming Languages'][0]+",JavaScript Frameworks: "+content['JavaScript Frameworks'][0]+",Web Servers: "+content["Web Servers"][0]+",CDN:"+content["CDN"][0],'time':'%.3f s' % self.time}
            except:
                return {'total':count,'url':self.url,'result':content['CMS'][0],'time':'%.3f s' % self.time}
        else:
            return {'total':count,'url':self.url,'result':'未知CMS','time':'%.3f s' % self.time}
    
    def getresult(self,url):
        response = requests.get(url,verify=False)
        #上面的代码可以随意发挥,只要获取到response即可
        #下面的代码您无需改变，直接使用即可
        whatweb_dict = {"url":response.url,"text":response.text,"headers":dict(response.headers)}
        whatweb_dict = json.dumps(whatweb_dict)
        whatweb_dict = whatweb_dict.encode()
        whatweb_dict = zlib.compress(whatweb_dict)
        data = {"info":whatweb_dict}
        return requests.post("http://whatweb.bugscaner.com/api.go",files=data)

