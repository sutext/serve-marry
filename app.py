from flask import Flask, jsonify, request, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql.sqltypes import TIMESTAMP
from sqlalchemy.sql import func
import urllib2
import json
import base64
from Crypto.Cipher import AES

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
db = SQLAlchemy(app)
appid = 'wx53f49d2dc35f4033'
secret = 'd7d2dc4ad3fb6ccb614320aa1e9c1401'

unknown = 'UNKNOWN'
ok = 'OK'
nouser = 'NOUSER'
paramerr = "PARAMERR"
wxerr = "WXERR"
syserr = 'SYSERR'


class User(db.Model):
    __tablename__ = 'user'
    openid = db.Column(db.String(40), primary_key=True)
    count = db.Column(db.Integer, default=1)
    avatar = db.Column(db.String(40))
    accept = db.Column(db.Boolean, default=False)
    nickname = db.Column(db.String(20))
    realname = db.Column(db.String(20))
    accept_time = db.Column(TIMESTAMP, server_default=func.now())
    session_key = db.Column(db.String(40))

    @property
    def dict(self):
        return {
            'openid': self.openid,
            'realname': self.realname,
            'count': self.count,
            'accept': self.accept,
            'nickname': self.nickname,
            'avatar': self.avatar,
        }


class Result:
    def __init__(self):
        self.code = unknown
        self.data = None
        self.message = None

    @property
    def dict(self):
        return {
            'code': self.code,
            'data': self.data,
            'message': self.message,
        }

    def json(self):
        jstr = json.dumps(self, default=lambda o: o.dict,
                          sort_keys=True, allow_nan=False, indent=4)
        resp = make_response(jstr)
        resp.headers['Content-Type'] = "application/json"
        return resp


class Decoder:
    def __init__(self, appid, session_key):
        self.appid = appid
        self.session_key = session_key

    def decrypt(self, encryptedData, iv):
        # base64 decode
        session_key = base64.b64decode(self.session_key)
        encryptedData = base64.b64decode(encryptedData)
        iv = base64.b64decode(iv)
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted = json.loads(self._unpad(cipher.decrypt(encryptedData)))
        if decrypted['watermark']['appid'] != self.appid:
            raise Exception('Invalid Buffer')
        return decrypted

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]


db.create_all()


@app.route('/user/login', methods=['POST'])
def login():
    result = Result()
    params = json.loads(request.data)
    code = params['code']
    if code == None:
        result.code = paramerr
        result.message = "params error"
        abort(result.json())
    response = urllib2.urlopen(
        'https://api.weixin.qq.com/sns/jscode2session?appid='+appid+'&secret='+secret+'&js_code='+code+'&grant_type=authorization_code')
    openinfo = json.loads(response.read())
    openid = openinfo["openid"]
    session_key = openinfo['session_key']
    if openid == None or session_key == None:
        result.code = wxerr
        result.message = "error from wx server"
        abort(result.json())
    user = User.query.filter(User.openid == openid).first()
    try:
        if user == None:
            user = User()
            user.openid = openid
            db.session.add(user)
        user.session_key = session_key
        db.session.commit()
        result.code = ok
        result.data = user
    except Exception, err:
        print(err)
        result.code = syserr
        result.message = "system error"
    return result.json()


@app.route('/user/accept', methods=['POST'])
def accept():
    result = Result()
    params = json.loads(request.data)
    print(params)
    openid = params['openid']
    iv = params['iv']
    encryptedData = params['encryptedData']
    if openid == None or iv == None or encryptedData == None:
        result.code = paramerr
        result.message = "params error"
        abort(result.json())
    user = User.query.filter(User.openid == openid).first()
    if user == None:
        result.code = nouser
        result.message = "user not exist"
        abort(result.json())
    try:
        decoder = Decoder(appid, user.session_key)
        userinfo = decoder.decrypt(encryptedData, iv)
        print(userinfo)
        user.openid = userinfo['openId']
        user.nickname = userinfo['nickName']
        user.avatar = userinfo['avatarUrl']
        user.accept = True
        # user.realname = params['realname']
        db.session.commit()
        result.code = ok
        result.data = user
    except Exception, err:
        print(err)
        result.code = syserr
        result.message = "system error"
    return result.json()


@app.route('/user/list', methods=['POST'])
def users():
    result = Result()
    try:
        data = User.query.filter(User.accept == True).all()
        result.code = ok
        result.data = data
    except Exception, err:
        print(err)
        result.code = syserr
        result.message = "system error"
    return result.json()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
