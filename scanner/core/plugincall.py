from functools import reduce
from ..app import plugins
from multiprocessing.dummy import Pool as ThreadPool


pool = ThreadPool(processes=20)
class callfunction:
    def __init__(self):
        self.angelswordType=list(plugins.angelsword.keys())
        self.angelswordFuncsDict = reduce(lambda x, y: dict(x, **y), list(plugins.angelsword.values()))
        self.result = []

    def pocscan(self,url):
        self.url=url
        pool.map_async(self._mapcall,self.angelswordFuncsDict.values(),callback=self.cookresult)
        print(self.result)
        pool.close()
        pool.join()
        return self.result

    def _mapcall(self,f):
        print(f(self.url).run())
        return f(self.url).run()

    def cookresult(self,pocResult):
        try:
            if "[+]" in pocResult:
                self.result.append(pocResult)
        except:
            print('process error')
            return 0


