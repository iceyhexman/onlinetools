# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, make_response
from .model.whatcms import gwhatweb
import re
import requests
import json
import socket
from .model.information.informationmain import *
from .model.industrial.industrialmain import *
from .model.hardware.hardwaremain import *

app = Flask(__name__)


def getjson():
    return json.loads(request.get_data())


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
    return render_template('information.html', title='信息泄露')


@app.route('/industrial')
def industrial_scan():
    return render_template('industrial.html', title='工控安全')


@app.route('/hardware')
def hardware_scan():
    return render_template('hardware.html', title='物联网安全')


@app.route('/py2img')
def py2img():
    return render_template('py2img.html', title='python转图像')


'''


api定义段


'''


# 查询
@app.route('/api/query', methods=['post'])
def query_c():
    post_json = getjson()
    request_json_raw = requests.get('http://www.webscan.cc/?action=query&ip=%s' % post_json[0]['ip'])
    return request_json_raw.content


# 文件下载
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
    information_poc = [options_method_BaseVerify,
                       git_check_BaseVerify,
                       jsp_conf_find_BaseVerify,
                       robots_find_BaseVerify,
                       svn_check_BaseVerify,
                       jetbrains_ide_workspace_disclosure_BaseVerify,
                       apache_server_status_disclosure_BaseVerify,
                       crossdomain_find_BaseVerify]

    information_poc_result = information_poc[information_type](information_url).run()
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
    industrial_poc =[wireless_monitor_priv_elevation_BaseVerify,
                     rockontrol_weak_BaseVerify,
                     sgc8000_sg8k_sms_disclosure_BaseVerify,
                     sgc8000_deldata_config_disclosure_BaseVerify,
                     sgc8000_defaultuser_disclosure_BaseVerify,
                     zte_wireless_getChannelByCountryCode_sqli_BaseVerify,
                     zte_wireless_weak_pass_BaseVerify,
                     dfe_scada_conf_disclosure_BaseVerify]
    industrial_poc_result = industrial_poc[industrial_type](industrial_url).run()
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
    hardware_poc = [router_dlink_webproc_fileread_BaseVerify,
                    router_dlink_command_exec_BaseVerify,
                    router_ruijie_unauth_BaseVerify,
                    adtsec_gateway_struts_exec_BaseVerify,
                    adtsec_Overall_app_js_bypass_BaseVerify,
                    mpsec_weakpass_exec_BaseVerify,
                    mpsec_webui_filedownload_BaseVerify,
                    camera_uniview_dvr_rce_BaseVerify,
                    printer_xerox_default_pwd_BaseVerify,
                    printer_hp_jetdirect_unauth_BaseVerify,
                    printer_topaccess_unauth_BaseVerify,
                    printer_canon_unauth_BaseVerify,
                    juniper_netscreen_backdoor_BaseVerify,
                    camera_hikvision_web_weak_BaseVerify]
    hardware_poc_result = hardware_poc[hardware_type](hardware_url).run()
    if "[+]" in hardware_poc_result:
        hardware_poc_status = 1
    else:
        hardware_poc_status = 0
    return jsonify({"status": hardware_poc_status, "pocresult": hardware_poc_result})

