#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: hardware漏洞库
referer: unknow
author: Lucifer
description: 包含所有hardware漏洞类型，封装成一个模块
'''

#router vulns
from .router.router_dlink_webproc_fileread import router_dlink_webproc_fileread_BaseVerify
from .router.router_dlink_command_exec import router_dlink_command_exec_BaseVerify
from .router.router_ruijie_unauth import router_ruijie_unauth_BaseVerify

#gateway vulns
from .gateway.adtsec_gateway_struts_exec import adtsec_gateway_struts_exec_BaseVerify
from .gateway.adtsec_Overall_app_js_bypass import adtsec_Overall_app_js_bypass_BaseVerify
from .gateway.mpsec_weakpass_exec import mpsec_weakpass_exec_BaseVerify
from .gateway.mpsec_webui_filedownload import mpsec_webui_filedownload_BaseVerify

#camera vulns
from .camera.camera_uniview_dvr_rce import camera_uniview_dvr_rce_BaseVerify
from .camera.camera_hikvision_web_weak import camera_hikvision_web_weak_BaseVerify

#printer vulns
from .printer.printer_xerox_default_pwd import printer_xerox_default_pwd_BaseVerify
from .printer.printer_hp_jetdirect_unauth import printer_hp_jetdirect_unauth_BaseVerify
from .printer.printer_topaccess_unauth import printer_topaccess_unauth_BaseVerify
from .printer.printer_canon_unauth import printer_canon_unauth_BaseVerify

#firewall vulns
from .firewall.juniper_netscreen_backdoor import juniper_netscreen_backdoor_BaseVerify