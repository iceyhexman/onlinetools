#coding=utf-8
from gevent import monkey
from gevent.pywsgi import WSGIServer
monkey.patch_all()
from scanner.app import app


if __name__ == '__main__':
    port=8000
    print("scanner is running,link:http://localhost:%d"% port)
    try:
        http_server = WSGIServer(('', port), app)
        http_server.serve_forever()
    except:
        print("Exit by User or Error")
