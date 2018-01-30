import gevent
from gevent.queue import Queue
import json
import hashlib
import time
import requests
import os



class gwhatweb(object):
    def __init__(self, url):
        self.tasks = Queue()
        self.url = url.rstrip('/')
        fp = open(os.getcwd()+'/cmsscan/scandata/cmslist1.json')
        webdata = json.load(fp, encoding='utf-8')
        for i in webdata:
            self.tasks.put(i)
        fp.close()
        self.total = len(webdata)

    def _GetMd5(self, body):
        m2 = hashlib.md5()
        m2.update(body)
        return m2.hexdigest()

    def _clearQueue(self):
        while not self.tasks.empty():
            self.tasks.get()

    def _worker(self):
        data = self.tasks.get()
        test_url = self.url + data['url']
        try:
            r = requests.get(test_url, timeout=10)
            if (r.status_code != 200):
                return
            rtext = r.text
            if rtext is None:
                return
        except:
            rtext = ''

        if data["re"]:
            if (rtext.find(data['re']) != -1):
                result = data['name']
                self.result = result
                self._clearQueue()
                return True
        else:
            try:
                md5 = self._GetMd5(rtext)
            except:
                md5 = ''
            if (md5 == data['md5']):
                result = data["name"]
                self.result = result
                self._clearQueue()
                return True

    def _boss(self):
        while not self.tasks.empty():
            self._worker()

    def whatweb(self,):
        maxsize = 1000
        start = time.clock()
        allr = [gevent.spawn(self._boss) for i in range(maxsize)]
        gevent.joinall(allr)
        end = time.clock()
        self.time = end - start
        return {'total':self.total,'url':self.url,'result':self.result,'time':'%.3f s' % self.time}

