from ..app import Blueprint
from scanner.core.plugincall import callfunction
user = Blueprint('user', __name__)

plugin=callfunction()

@user.route("/home",methods=["get","post"])
def home():
    return str(plugin.pocscan("http://cn.changhong.com/"))

