from ..app import app,json,requests,request,make_response,socket,jsonify,Blueprint,plugins

api = Blueprint('api', __name__)

def getjson():
    return json.loads(request.get_data().decode("utf-8"))
# webscan.cc结果查询

@api.route('/query', methods=['post'])
def query_c():
    post_json = getjson()
    request_json_raw = requests.get('http://www.webscan.cc/?action=query&ip=%s' % post_json[0]['ip'])
    return request_json_raw.content


# 结果下载
@api.route('/download', methods=['POST'])
def download_file():
    content = request.form.get("save")
    response = make_response(content.replace("|", "\n"))
    response.headers['Content-Disposition'] = 'attachment; filename=data.txt'
    return response


# domain2ip
@api.route('/domain2ip', methods=['POST'])
def return_json():
    domain_json = getjson()
    ip = socket.gethostbyname(domain_json[0]['domain'].split('/')[2])
    j_ip = [{"ip": ip}]
    return jsonify(j_ip)


# thread_start
@api.route('/thread', methods=['post'])
def thread_start():
    thread_ip = getjson()
    thread_json_raw = requests.get('http://webscan.cc/thread.php?ip=%s' % thread_ip[0]['ip'])
    return thread_json_raw.content


# 信息泄露
@api.route('/information', methods=['post'])
def information_api():
    information_load = getjson()
    information_url = information_load['url']
    information_type = information_load['type']
    information_poc_result = list(plugins.angelsword['informationpocdict'].values())[information_type](information_url).run()
    if "[+]" in information_poc_result:
        information_poc_status = 1
    else:
        information_poc_status = 0
    return jsonify({"status": information_poc_status, "pocresult": information_poc_result})


# 工控安全
@api.route('/industrial', methods=['post'])
def industrial_api():
    industrial_load = getjson()
    industrial_url = industrial_load['url']
    industrial_type = industrial_load['type']
    industrial_poc_result = list(plugins.angelsword['industrialpocdict'].values())[industrial_type](industrial_url).run()
    if "[+]" in industrial_poc_result:
        industrial_poc_status = 1
    else:
        industrial_poc_status = 0
    return jsonify({"status": industrial_poc_status, "pocresult": industrial_poc_result})


# 物联网安全
@api.route('/hardware', methods=['post'])
def hardware_api():
    hardware_load = getjson()
    hardware_url = hardware_load['url']
    hardware_type = hardware_load['type']
    hardware_poc_result = list(plugins.angelsword['hardwarepocdict'].values())[hardware_type](hardware_url).run()
    if "[+]" in hardware_poc_result:
        hardware_poc_status = 1
    else:
        hardware_poc_status = 0
    return jsonify({"status": hardware_poc_status, "pocresult": hardware_poc_result})


# system安全
@api.route('/system', methods=['post'])
def system_api():
    system_load = getjson()
    system_url = system_load['url']
    system_type = system_load['type']
    system_poc_result = list(plugins.angelsword['systempocdict'].values())[system_type](system_url).run()
    if "[+]" in system_poc_result:
        system_poc_status = 1
    else:
        system_poc_status = 0
    return jsonify({"status": system_poc_status, "pocresult": system_poc_result})


# cms漏洞利用
@api.route('/cms', methods=['post'])
def cms_api():
    cmsexp_load = getjson()
    cmsexp_url = cmsexp_load['url']
    cmsexp_type = cmsexp_load['type']
    cmsexp_poc_result = list(plugins.angelsword['cmspocdict'].values())[cmsexp_type](cmsexp_url).run()
    if cmsexp_poc_result is not None:
        if "[+]" in cmsexp_poc_result:
            cmsexp_poc_status = 1
        else:
            cmsexp_poc_status = 0
    else:
        cmsexp_poc_result = "[-]no vuln"
        cmsexp_poc_status = 0
    return jsonify({"status": cmsexp_poc_status, "pocresult": cmsexp_poc_result})

@api.route('/subdomain',methods=['post'])
def subdomain_api():
    domain_json=getjson()
    return requests.get("http://ce.baidu.com/index/getRelatedSites?site_address={domain}".format(domain=domain_json['domain'])).text

@api.route('/nmap',methods=['post'])
def nmap_api():
    target_json=getjson()
    return jsonify({'data':requests.get("https://api.hackertarget.com/nmap/?q={target}".format(target=target_json['target'].replace("http:","").replace("https:","").replace("/",""))).text})
