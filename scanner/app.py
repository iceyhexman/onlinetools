from flask import Flask, render_template, \
    request, jsonify,make_response, Markup,session
import re
import requests
import socket
import json
from flask import Blueprint
import flask_login
from .pluginloader import *
app = Flask(__name__)
app.config.update(DEBUG=True)
plugins = pluginMain()
from .controller.publicview import *
from .controller.apiroute import *
from .controller.userview import *
app.register_blueprint(api, url_prefix="/api")
app.register_blueprint(user, url_prefix="/user")

