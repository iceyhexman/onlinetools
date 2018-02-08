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
from .model.system.systemmain import *
from .model.cms.cmsmain import *

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


@app.route('/system')
def system_scan():
    return render_template('system.html', title='system安全')


@app.route('/cms')
def cms_scan():
    return render_template('cms.html', title='cms安全检测')


@app.route('/search')
def search():
    return render_template('/search.html', title='搜索')


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
    industrial_poc = [wireless_monitor_priv_elevation_BaseVerify,
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


# system安全
@app.route('/api/system', methods=['post'])
def system_api():
    system_load = getjson()
    system_url = system_load['url']
    system_type = system_load['type']
    system_poc = [couchdb_unauth_BaseVerify,
                  zookeeper_unauth_BaseVerify,
                  goahead_LD_PRELOAD_rce_BaseVerify,
                  topsec_change_lan_filedownload_BaseVerify,
                  tomcat_put_exec_BaseVerify,
                  redis_unauth_BaseVerify,
                  kinggate_zebra_conf_BaseVerify,
                  multi_fastcgi_code_exec_BaseVerify,
                  turbomail_conf_BaseVerify,
                  turbogate_services_xxe_BaseVerify,
                  weblogic_ssrf_BaseVerify,
                  weblogic_xmldecoder_exec_BaseVerify,
                  weblogic_interface_disclosure_BaseVerify,
                  forease_fileinclude_code_exec_BaseVerify,
                  hudson_ws_disclosure_BaseVerify,
                  npoint_mdb_download_BaseVerify,
                  zkeys_database_conf_BaseVerify,
                  hac_gateway_info_disclosure_BaseVerify,
                  moxa_oncell_telnet_BaseVerify,
                  glassfish_fileread_BaseVerify,
                  zabbix_jsrpc_profileIdx2_sqli_BaseVerify,
                  php_fastcgi_read_BaseVerify,
                  php_expose_disclosure_BaseVerify,
                  hfs_rejetto_search_rce_BaseVerify,
                  shellshock_BaseVerify,
                  dorado_default_passwd_BaseVerify,
                  iis_ms15034_httpsys_rce_BaseVerify,
                  iis_webdav_rce_BaseVerify,
                  srun_index_file_filedownload_BaseVerify,
                  srun_rad_online_bypass_rce_BaseVerify,
                  srun_rad_online_username_rce_BaseVerify,
                  srun_download_file_filedownload_BaseVerify,
                  srun_user_info_uid_rce_BaseVerify,
                  intel_amt_crypt_bypass_BaseVerify,
                  smtp_starttls_plaintext_inj_BaseVerify,
                  resin_viewfile_fileread_BaseVerify,
                  mongodb_unauth_BaseVerify,
                  sangfor_ad_script_command_exec_BaseVerify]
    system_poc_result = system_poc[system_type](system_url).run()
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
    cmsexp_poc = [weaver_oa_filedownload_BaseVerify,
                  weaver_oa_download_sqli_BaseVerify,
                  weaver_oa_db_disclosure_BaseVerify,
                  phpok_res_action_control_filedownload_BaseVerify,
                  phpok_api_param_sqli_BaseVerify,
                  phpok_remote_image_getshell_BaseVerify,
                  jeecg_pwd_reset_BaseVerify,
                  typecho_install_code_exec_BaseVerify,
                  foosun_City_ajax_sqli_BaseVerify,
                  autoset_phpmyadmin_unauth_BaseVerify,
                  phpstudy_probe_BaseVerify,
                  phpstudy_phpmyadmin_defaultpwd_BaseVerify,
                  discuz_forum_message_ssrf_BaseVerify,
                  discuz_focus_flashxss_BaseVerify,
                  discuz_x25_path_disclosure_BaseVerify,
                  discuz_plugin_ques_sqli_BaseVerify,
                  hishop_productlist_sqli_BaseVerify,
                  eyou_weakpass_BaseVerify,
                  eyou_admin_id_sqli_BaseVerify,
                  eyou_resetpw_BaseVerify,
                  eyou_user_kw_sqli_BaseVerify,
                  kingdee_filedownload_BaseVerify,
                  kingdee_resin_dir_path_disclosure_BaseVerify,
                  kingdee_conf_disclosure_BaseVerify,
                  kingdee_logoImgServlet_fileread_BaseVerify,
                  looyu_down_filedownload_BaseVerify,
                  smartoa_multi_filedownload_BaseVerify,
                  urp_query_BaseVerify,
                  urp_query2_BaseVerify,
                  urp_ReadJavaScriptServlet_fileread_BaseVerify,
                  pkpmbs_guestbook_sqli_BaseVerify,
                  pkpmbs_addresslist_keyword_sqli_BaseVerify,
                  pkpmbs_MsgList_sqli_BaseVerify,
                  dyp2p_latesindex_sqli_BaseVerify,
                  dyp2p_url_fileread_BaseVerify,
                  igenus_code_exec_BaseVerify,
                  igenus_login_Lang_fileread_BaseVerify,
                  igenus_syslogin_Lang_fileread_BaseVerify,
                  live800_downlog_filedownload_BaseVerify,
                  live800_loginAction_sqli_BaseVerify,
                  live800_sta_export_sqli_BaseVerify,
                  live800_services_xxe_BaseVerify,
                  onethink_category_sqli_BaseVerify,
                  thinkphp_code_exec_BaseVerify,
                  wizbank_download_filedownload_BaseVerify,
                  wizbank_usr_id_sqli_BaseVerify,
                  domino_unauth_BaseVerify,
                  hjsoft_sqli_BaseVerify,
                  hnkj_researchinfo_dan_sqli_BaseVerify,
                  libsys_ajax_asyn_link_old_fileread_BaseVerify,
                  libsys_ajax_asyn_link_fileread_BaseVerify,
                  libsys_ajax_get_file_fileread_BaseVerify,
                  gpower_users_disclosure_BaseVerify,
                  metinfo_getpassword_sqli_BaseVerify,
                  yonyou_icc_struts2_BaseVerify,
                  v2Conference_sqli_xxe_BaseVerify,
                  gpcsoft_ewebeditor_weak_BaseVerify,
                  rap_interface_struts_exec_BaseVerify,
                  hongan_dlp_struts_exec_BaseVerify,
                  jiuyu_library_struts_exec_BaseVerify,
                  yaojie_steel_struts_exec_BaseVerify,
                  digital_campus_log_disclosure_BaseVerify,
                  digital_campus_systemcodelist_sqli_BaseVerify,
                  jeecms_fpath_filedownload_BaseVerify,
                  shopex_phpinfo_disclosure_BaseVerify,
                  dkcms_database_disclosure_BaseVerify,
                  finecms_uploadfile_BaseVerify,
                  damall_selloffer_sqli_BaseVerify,
                  hanweb_readxml_fileread_BaseVerify,
                  hanweb_downfile_filedownload_BaseVerify,
                  hanweb_VerifyCodeServlet_install_BaseVerify,
                  php168_login_getshell_BaseVerify,
                  dedecms_version_BaseVerify,
                  dedecms_search_typeArr_sqli_BaseVerify,
                  dedecms_error_trace_disclosure_BaseVerify,
                  dedecms_download_redirect_BaseVerify,
                  dedecms_recommend_sqli_BaseVerify,
                  umail_physical_path_BaseVerify,
                  umail_sessionid_access_BaseVerify,
                  metinfo_login_check_sqli_BaseVerify,
                  yonyou_user_ids_sqli_BaseVerify,
                  yonyou_multi_union_sqli_BaseVerify,
                  yonyou_initData_disclosure_BaseVerify,
                  yonyou_createMysql_disclosure_BaseVerify,
                  yonyou_test_sqli_BaseVerify,
                  yonyou_getemaildata_fileread_BaseVerify,
                  yonyou_ehr_ELTextFile_BaseVerify,
                  yonyou_a8_CmxUser_sqli_BaseVerify,
                  yonyou_a8_logs_disclosure_BaseVerify,
                  yonyou_status_default_pwd_BaseVerify,
                  yonyou_a8_personService_xxe_BaseVerify,
                  yonyou_cm_info_content_sqli_BaseVerify,
                  yonyou_u8_CmxItem_sqli_BaseVerify,
                  yonyou_fe_treeXml_sqli_BaseVerify,
                  yonyou_ehr_resetpwd_sqli_BaseVerify,
                  yonyou_nc_NCFindWeb_fileread_BaseVerify,
                  fsmcms_p_replydetail_sqli_BaseVerify,
                  fsmcms_setup_reinstall_BaseVerify,
                  fsmcms_columninfo_sqli_BaseVerify,
                  qibocms_search_sqli_BaseVerify,
                  qibocms_search_code_exec_BaseVerify,
                  qibocms_js_f_id_sqli_BaseVerify,
                  qibocms_s_fids_sqli_BaseVerify,
                  yeu_disclosure_uid_BaseVerify,
                  inspur_multi_sqli_BaseVerify,
                  inspur_ecgap_displayNewsPic_sqli_BaseVerify,
                  clib_kinweblistaction_download_BaseVerify,
                  clib_kindaction_fileread_BaseVerify,
                  gobetters_multi_sqli_BaseVerify,
                  lbcms_webwsfw_bssh_sqli_BaseVerify,
                  euse_study_multi_sqli_BaseVerify,
                  suntown_upfile_fileupload_BaseVerify,
                  dswjcms_p2p_multi_sqli_BaseVerify,
                  skytech_bypass_priv_BaseVerify,
                  wordpress_plugin_azonpop_sqli_BaseVerify,
                  wordpress_plugin_ShortCode_lfi_BaseVerify,
                  wordpress_url_redirect_BaseVerify,
                  wordpress_woocommerce_code_exec_BaseVerify,
                  wordpress_plugin_mailpress_rce_BaseVerify,
                  wordpress_admin_ajax_filedownload_BaseVerify,
                  wordpress_restapi_sqli_BaseVerify,
                  wordpress_display_widgets_backdoor_BaseVerify,
                  mallbuilder_change_status_sqli_BaseVerify,
                  efuture_downloadAct_filedownload_BaseVerify,
                  kj65n_monitor_sqli_BaseVerify,
                  piaoyou_multi_sqli_BaseVerify,
                  piaoyou_ten_sqli_BaseVerify,
                  piaoyou_six_sqli_BaseVerify,
                  piaoyou_six2_sqli_BaseVerify,
                  piaoyou_int_order_sqli_BaseVerify,
                  piaoyou_newsview_list_BaseVerify,
                  sinda_downloadfile_download_BaseVerify,
                  lianbang_multi_bypass_priv_BaseVerify,
                  star_PostSuggestion_sqli_BaseVerify,
                  tcexam_reinstall_getshell_BaseVerify,
                  hezhong_list_id_sqli_BaseVerify,
                  zuitu_coupon_id_sqli_BaseVerify,
                  cicro_DownLoad_filedownload_BaseVerify,
                  huaficms_bypass_js_BaseVerify,
                  iwms_bypass_js_delete_BaseVerify,
                  nongyou_multi_sqli_BaseVerify,
                  nongyou_Item2_sqli_BaseVerify,
                  nongyou_ShowLand_sqli_BaseVerify,
                  nongyou_sleep_sqli_BaseVerify,
                  zfcgxt_UserSecurityController_getpass_BaseVerify,
                  mainone_b2b_Default_sqli_BaseVerify,
                  mainone_SupplyList_sqli_BaseVerify,
                  mainone_ProductList_sqli_BaseVerify,
                  xplus_2003_getshell_BaseVerify,
                  xplus_mysql_mssql_sqli_BaseVerify,
                  workyi_multi_sqli_BaseVerify,
                  newedos_multi_sqli_BaseVerify,
                  uniportal_bypass_priv_sqli_BaseVerify,
                  pageadmin_forge_viewstate_BaseVerify,
                  xtcms_download_filedownload_BaseVerify,
                  ruvar_oa_multi_sqli_BaseVerify,
                  ruvar_oa_multi_sqli2_BaseVerify,
                  ruvar_oa_multi_sqli3_BaseVerify,
                  gn_consulting_sqli_BaseVerify,
                  jumboecms_slide_id_sqli_BaseVerify,
                  joomla_com_docman_lfi_BaseVerify,
                  joomla_index_list_sqli_BaseVerify,
                  caitong_multi_sqli_BaseVerify,
                  alkawebs_viewnews_sqli_BaseVerify,
                  caitong_multi_sleep_sqli_BaseVerify,
                  shop360_do_filedownload_BaseVerify,
                  pstar_warehouse_msg_01_sqli_BaseVerify,
                  pstar_isfLclInfo_sqli_BaseVerify,
                  pstar_qcustoms_sqli_BaseVerify,
                  trs_wcm_pre_as_lfi_BaseVerify,
                  trs_inforadar_disclosure_BaseVerify,
                  trs_lunwen_papercon_sqli_BaseVerify,
                  trs_infogate_xxe_BaseVerify,
                  trs_infogate_register_BaseVerify,
                  trs_was5_config_disclosure_BaseVerify,
                  trs_was5_download_templet_BaseVerify,
                  trs_wcm_default_user_BaseVerify,
                  trs_wcm_infoview_disclosure_BaseVerify,
                  trs_was40_passwd_disclosure_BaseVerify,
                  trs_was40_tree_disclosure_BaseVerify,
                  trs_ids_auth_disclosure_BaseVerify,
                  trs_wcm_service_writefile_BaseVerify,
                  ecscms_MoreIndex_sqli_BaseVerify,
                  gowinsoft_jw_multi_sqli_BaseVerify,
                  siteserver_background_taskLog_sqli_BaseVerify,
                  siteserver_background_log_sqli_BaseVerify,
                  siteserver_UserNameCollection_sqli_BaseVerify,
                  siteserver_background_keywordsFilting_sqli_BaseVerify,
                  siteserver_background_administrator_sqli_BaseVerify,
                  nitc_suggestwordList_sqli_BaseVerify,
                  nitc_index_language_id_sqli_BaseVerify,
                  ndstar_six_sqli_BaseVerify,
                  eis_menu_left_edit_sqli_BaseVerify,
                  tianbo_Type_List_sqli_BaseVerify,
                  tianbo_TCH_list_sqli_BaseVerify,
                  tianbo_Class_Info_sqli_BaseVerify,
                  tianbo_St_Info_sqli_BaseVerify,
                  acsoft_GetXMLList_fileread_BaseVerify,
                  acsoft_GetFile_fileread_BaseVerify,
                  acsoft_GetFileContent_fileread_BaseVerify,
                  gxwssb_fileDownloadmodel_download_BaseVerify,
                  etmdcp_Load_filedownload_BaseVerify,
                  anmai_grghjl_stuNo_sqli_BaseVerify,
                  nongyou_ShowLand_sqli_BaseVerify,
                  zf_cms_FileDownload_BaseVerify,
                  shiyou_list_keyWords_sqli_BaseVerify,
                  speedcms_list_cid_sqli_BaseVerify,
                  zhuofan_downLoadFile_download_BaseVerify,
                  gevercms_downLoadFile_filedownload_BaseVerify,
                  weway_PictureView1_filedownload_BaseVerify,
                  esccms_selectunitmember_unauth_BaseVerify,
                  wecenter_topic_id_sqli_BaseVerify,
                  shopnum_ShoppingCart1_sqli_BaseVerify,
                  shopnum_ProductListCategory_sqli_BaseVerify,
                  shopnum_ProductDetail_sqli_BaseVerify,
                  shopnum_GuidBuyList_sqli_BaseVerify,
                  fastmeeting_download_filedownload_BaseVerify,
                  viewgood_two_sqli_BaseVerify,
                  viewgood_pic_proxy_sqli_BaseVerify,
                  viewgood_GetCaption_sqli_BaseVerify,
                  shop7z_order_checknoprint_sqli_BaseVerify,
                  dreamgallery_album_id_sqli_BaseVerify,
                  ips_community_suite_code_exec_BaseVerify,
                  kxmail_login_server_sqli_BaseVerify,
                  shopnc_index_class_id_sqli_BaseVerify,
                  skytech_geren_list_page_sqli_BaseVerify,
                  xuezi_ceping_unauth_BaseVerify,
                  shadowsit_selector_lfi_BaseVerify,
                  haohan_FileDown_filedownload_BaseVerify,
                  phpcms_digg_add_sqli_BaseVerify,
                  phpcms_authkey_disclosure_BaseVerify,
                  phpcms_flash_upload_sqli_BaseVerify,
                  phpcms_product_code_exec_BaseVerify,
                  phpcms_v96_sqli_BaseVerify,
                  phpcms_v961_fileread_BaseVerify,
                  phpcms_v9_flash_xss_BaseVerify,
                  seacms_search_code_exec_BaseVerify,
                  seacms_order_code_exec_BaseVerify,
                  seacms_search_jq_code_exec_BaseVerify,
                  anmai_teachingtechnology_sqli_BaseVerify,
                  cmseasy_header_detail_sqli_BaseVerify,
                  phpmyadmin_setup_lfi_BaseVerify,
                  opensns_index_arearank_BaseVerify,
                  opensns_index_getshell_BaseVerify,
                  ecshop_uc_code_sqli_BaseVerify,
                  ecshop_flow_orderid_sqli_BaseVerify,
                  siteengine_comments_module_sqli_BaseVerify,
                  mingteng_cookie_deception_BaseVerify,
                  zfsoft_service_stryhm_sqli_BaseVerify,
                  zfsoft_database_control_BaseVerify,
                  zfsoft_default3_bruteforce_BaseVerify,
                  v2Conference_sqli_xxe_BaseVerify,
                  jxt1039_unauth_BaseVerify,
                  thinksns_category_code_exec_BaseVerify,
                  tpshop_eval_stdin_code_exec_BaseVerify]
    cmsexp_poc_result = cmsexp_poc[cmsexp_type](cmsexp_url).run()
    if cmsexp_poc_result is not None:
        if "[+]" in cmsexp_poc_result:
            cmsexp_poc_status = 1
        else:
            cmsexp_poc_status = 0
    else:
        cmsexp_poc_result = "[-]no vuln"
        cmsexp_poc_status = 0
    return jsonify({"status": cmsexp_poc_status, "pocresult": cmsexp_poc_result})
