# -*- coding: utf-8 -*-
from flask import Flask, render_template, \
    request, jsonify,make_response, Markup
from .model.whatcms import gwhatweb
import re
import requests
import json
import socket
from .pocdata import *
from .plugins import *


app = Flask(__name__)


def getjson():
    return json.loads(request.get_data().decode("utf-8"))


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/whatcms', methods=['get', 'post'])
def whatcms():
    if request.method == 'POST':
        url = request.form.get("url")
        if re.match(r'^https?:/{2}\w.+$', url):
            try:
                whatcmsresult = gwhatweb(url).whatweb()
                return render_template('whatcms.html', data=whatcmsresult, title='CMS识别')
            except:
                whatcmsresult = {'total': '', 'url': '', 'result': '', 'time': ''}
                return render_template('whatcms.html', data=whatcmsresult, title='CMS识别')
    else:
        return render_template('whatcms.html', title="CMS识别")


@app.route('/jsfuck')
def jsfuck():
    return render_template('jsfuck.html', title='jsfuck解密')


@app.route('/getdomain')
def getdomin():
    return render_template('getdomain.html', title='旁站/C段')


@app.route('/information')
def information_scan():
    return render_template('information.html', title='信息泄露', data=Markup(list(informationpocdict.keys())))


@app.route('/industrial')
def industrial_scan():
    return render_template('industrial.html', title='工控安全', data=Markup(list(industrialpocdict.keys())))


@app.route('/hardware')
def hardware_scan():
    return render_template('hardware.html', title='物联网安全', data=Markup(list(hardwarepocdict.keys())))


@app.route('/system')
def system_scan():
    return render_template('system.html', title='system安全', data=Markup(list(systempocdict.keys())))


@app.route('/cms')
def cms_scan():
    return render_template('cms.html', title='cms安全检测', data=Markup(list(cmspocdict.keys())))


@app.route('/search')
def search():
    dicts={"cms": Markup(list(cmspocdict.keys())), "industrial": Markup(list(industrialpocdict.keys())), "hardware": Markup(list(hardwarepocdict.keys())),"information": Markup(list(informationpocdict.keys())),"system": Markup(list(systempocdict.keys()))}
    return render_template('/search.html', title='搜索',data=dicts)



@app.route('/test')
def websockettest():
    return render_template('websocket.html',title='websocket')

@app.route('/subdomain')
def subdomain():
    return render_template('subdomain.html',title='子域名获取')




'''

api定义段

'''


# webscan.cc结果查询
@app.route('/api/query', methods=['post'])
def query_c():
    post_json = getjson()
    request_json_raw = requests.get('http://www.webscan.cc/?action=query&ip=%s' % post_json[0]['ip'])
    return request_json_raw.content


# 结果下载
@app.route('/api/download', methods=['POST'])
def download_file():
    content = request.form.get("save")
    response = make_response(content.replace("|", "\n"))
    response.headers['Content-Disposition'] = 'attachment; filename=data.txt'
    return response


# domain2ip
@app.route('/api/domain2ip', methods=['POST'])
def return_json():
    domain_json = getjson()
    ip = socket.gethostbyname(domain_json[0]['domain'].split('/')[2])
    j_ip = [{"ip": ip}]
    return jsonify(j_ip)


# thread_start
@app.route('/api/thread', methods=['post'])
def thread_start():
    thread_ip = getjson()
    thread_json_raw = requests.get('http://webscan.cc/thread.php?ip=%s' % thread_ip[0]['ip'])
    return thread_json_raw.content


# 信息泄露
@app.route('/api/information', methods=['post'])
def information_api():
    information_load = getjson()
    information_url = information_load['url']
    information_type = information_load['type']
    information_poc_result = list(informationpocdict.values())[information_type](information_url).run()
    if "[+]" in information_poc_result:
        information_poc_status = 1
    else:
        information_poc_status = 0
    return jsonify({"status": information_poc_status, "pocresult": information_poc_result})


# 工控安全
@app.route('/api/industrial', methods=['post'])
def industrial_api():
    industrial_load = getjson()
    industrial_url = industrial_load['url']
    industrial_type = industrial_load['type']
    industrial_poc_result = list(industrialpocdict.values())[industrial_type](industrial_url).run()
    if "[+]" in industrial_poc_result:
        industrial_poc_status = 1
    else:
        industrial_poc_status = 0
    return jsonify({"status": industrial_poc_status, "pocresult": industrial_poc_result})


# 物联网安全
@app.route('/api/hardware', methods=['post'])
def hardware_api():
    hardware_load = getjson()
    hardware_url = hardware_load['url']
    hardware_type = hardware_load['type']
    hardware_poc_result = list(hardwarepocdict.values())[hardware_type](hardware_url).run()
    if "[+]" in hardware_poc_result:
        hardware_poc_status = 1
    else:
        hardware_poc_status = 0
    return jsonify({"status": hardware_poc_status, "pocresult": hardware_poc_result})


# system安全
@app.route('/api/system', methods=['post'])
def system_api():
    system_load = getjson()
    system_url = system_load['url']
    system_type = system_load['type']
    system_poc_result = list(systempocdict.values())[system_type](system_url).run()
    if "[+]" in system_poc_result:
        system_poc_status = 1
    else:
        system_poc_status = 0
    return jsonify({"status": system_poc_status, "pocresult": system_poc_result})


# cms漏洞利用
@app.route('/api/cms', methods=['post'])
def cms_api():
    cmsexp_load = getjson()
    cmsexp_url = cmsexp_load['url']
    cmsexp_type = cmsexp_load['type']
    cmsexp_poc_result = list(cmspocdict.values())[cmsexp_type](cmsexp_url).run()
    if cmsexp_poc_result is not None:
        if "[+]" in cmsexp_poc_result:
            cmsexp_poc_status = 1
        else:
            cmsexp_poc_status = 0
    else:
        cmsexp_poc_result = "[-]no vuln"
        cmsexp_poc_status = 0
    return jsonify({"status": cmsexp_poc_status, "pocresult": cmsexp_poc_result})



@app.route('/api/subdomain',methods=['post'])
def subdomain_api():
    domain_json=getjson()
    return requests.get("http://ce.baidu.com/index/getRelatedSites?site_address={domain}".format(domain=domain_json['domain'])).text
