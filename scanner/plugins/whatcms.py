#coding=utf-8
import requests
import json
import time

class gwhatweb:
    def __init__(self,url):
        self.url = url
        self.time=0

    def whatweb(self):
        url = 'http://whatweb.bugscaner.com/what/'
        start = time.clock()
        headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0','Referer':'http://whatweb.bugscaner.com/look/'}
        cocokies = {'saeut': 'CkMPHlqbqdBQWl9NBG+uAg=='}
        new_url = self.url.strip('/').replace('http://','').replace('https://','')
        data = {'url': new_url}
        content = json.loads(requests.post(url,headers=headers,data=data).text)
        end = time.clock()
        self.time = end - start
        if content['CMS']:
            try:
                return {'total':1424,'url':self.url,'result':"CMS: "+content['CMS']+",JavaScript Frameworks: "+content['JavaScript Frameworks'][0]+",Web Servers: "+content["Web Servers"][0],'time':'%.3f s' % self.time}
            except:
                return {'total':1424,'url':self.url,'result':content['CMS'],'time':'%.3f s' % self.time}
        else:
            return {'total':1424,'url':self.url,'result':'未知CMS','time':'%.3f s' % self.time}
