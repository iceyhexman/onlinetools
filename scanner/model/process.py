from ..orm import Base
from sqlalchemy import Column,Integer,String
from base64 import b64encode
import hashlib

class Scanover(Base):
    __tablename__ = 'process'
    id = Column(Integer, primary_key=True)
    url = Column(String(100), unique=True)
    token = Column(String(50),unique=True)
    result = Column(String(3000))

    def __init__(self, url="", result="[]"):
        self.url = url
        self.token = hashlib.md5(b64encode(self.url.encode('utf-8'))).hexdigest()
        self.result = result

    def __repr__(self):
        return '<process %r>' % (self.url)