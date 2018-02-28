from cmsscan import app
from cmsscan import config
from gevent import monkey
from gevent.pywsgi import WSGIServer
monkey.patch_all()


if __name__ == '__main__':
    http_server = WSGIServer(('', 8000), app)
    http_server.serve_forever()