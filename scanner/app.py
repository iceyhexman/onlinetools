# -*- coding: utf-8 -*-
from flask import Flask, render_template, \
    request, jsonify,make_response, Markup
import re
import requests
import socket
import json
from flask import Blueprint
from .pocdata import *
app = Flask(__name__)
app.config.update(DEBUG=True)
plugins = pluginMain()

from .controller.publicview import *
from .controller.apiroute import *
app.register_blueprint(api, url_prefix="/api")


