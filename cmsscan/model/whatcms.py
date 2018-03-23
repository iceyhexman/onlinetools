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
        data = {'url': new_url, 'hash': '0eca8914342fc63f5a2ef5246b7a3b14_7289fd8cf7f420f594ac165e475f1479'}
        content = json.loads(requests.post(url,headers=headers,data=data).content)
        end = time.clock()
        self.time = end - start
        return {'total':1424,'url':self.url,'result':content['cms'],'time':'%.3f s' % self.time}
