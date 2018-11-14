#coding=utf-8
from gevent import monkey
from gevent.pywsgi import WSGIServer
monkey.patch_all()
from scanner.app import app
# import os


if __name__ == '__main__':
    port=8000
    print("scanner is running,link:http://localhost:%d"% port)
    ''' 进行中，待完成
    if os.path.exists('secret_key.key'):
        with open('secret_key.key',"r") as f:
            app.secret_key=f.read()
    else:
        with open('secret_key.key',"w") as f:
            f.write(str(os.urandom(24)))

    if not os.path.exists('./scan.db'):
        print(os.popen("python3 ./scanner/orm.py").read())
    '''
    try:
        http_server = WSGIServer(('', port), app)
        http_server.serve_forever()
    except:
        print("Exit by User or Error")
