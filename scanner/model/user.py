from ..orm import Base,db_session
from sqlalchemy import Column,Integer,String
from base64 import b64encode
import hashlib

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True)
    passwd = Column(String(120))
    token = Column(String(100),unique=True)
    target = Column(String(3000))

    def __init__(self, name="", passwd=""):
        self.name = name
        self.passwd = passwd
        self.token = hashlib.md5(b64encode(name.encode("utf-8"))+b64encode(passwd.encode("utf-8"))).hexdigest()
        self.target = "[]"

    def commit(self):
        db_session.add(self)
        db_session.commit()

    def __repr__(self):
        return '<User %r>' % (self.name)