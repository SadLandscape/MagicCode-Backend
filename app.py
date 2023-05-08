from typing import TYPE_CHECKING
from flask.app import Flask,request
from flask import Response,jsonify
import secrets,flask,flask_sock,json,hashlib,uuid
from flask_sqlalchemy import SQLAlchemy
from flask_sock import Sock

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.sqlite3"
db = SQLAlchemy(app)
sock = Sock(app)
client_list = {}

class Member(db.Model):
    __tablename__ = "members"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(), db.ForeignKey('users.id'), nullable=False)
    note_id = db.Column(db.String(), db.ForeignKey('notes.id'), nullable=False)
    can_edit = db.Column(db.Boolean, default=False)

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(), primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    authToken = db.Column(db.String(),nullable=False)
    display_name = db.Column(db.String(40),nullable=False)
    notes = db.relationship('Note', backref='author')
    def to_dict(self):
        return {"id":self.id,"username":self.username,"displayName":self.display_name,"email":self.email,"notes":[note.to_dict() for note in self.notes]}

class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.String(),primary_key=True)
    description = db.Column(db.Text,nullable=True)
    title = db.Column(db.String,nullable=False)
    access_code = db.Column(db.String,nullable=False)
    author_id = db.Column(db.String(), db.ForeignKey('users.id'))
    members = db.relationship('Member', backref='note')
    def to_dict(self,can_share=True,show_owner=False):
        data = {"id":self.id,"title":self.title,"body":self.description}
        if can_share:
            data.update({"shareToken":self.access_code})
        if show_owner:
            data.update({"author":self.author.to_dict()})
        return data

"""
OPCODES:
0 - auth
1 - ping
2 - subscribe
3 - unsubscribe

PAYLOAD MODELS:
0 - {"opcode":0,"auth_token":"32 bit secrets token"} -> {"status":1/0,"username":"username","email":"email","notes":[],"display_name":"display name"}
1 - {"opcode":1} -> {"status":1}
2 - {"opcode":2,"note_id":"note_id"} -> {"text":"text"}
3 - {"opcode":3,"note_id":"note_id"} -> {"status":1}
"""

@app.route("/api/notes/<uuid:note_id>",methods=["GET","POST","PATCH"])
def get_note(note_id):
    if request.method == "GET":
        pass

@app.route("/api/auth/register",methods=["POST"])
def register():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']
    if db.session.query(User).filter_by(username=username).first():
        response = {"error":"Username already exists!"}
        return (jsonify(**response),400)
    if db.session.query(User).filter_by(email=email).first():
        return (jsonify(error="This email is already registered!"),400)
    user = User(username=username,email=email,password=hashlib.md5(password.encode()).hexdigest(),id=uuid.uuid4().__str__(),display_name=username,authToken=secrets.token_hex(32))
    db.session.add(user)
    db.session.commit()
    return jsonify(**{**user.to_dict(),**{"authToken":user.authToken,"message":"Successfull registered!"}})

@app.route("/api/auth/login",methods=["POST"])
def login():
    email = request.json['email']
    password = request.json['password']
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    requested_user = db.session.query(User).filter_by(email=email).first()
    if not requested_user:
        return (jsonify(error="No such user with the given email address exists!"),400)
    if not pw_hash == requested_user.password:
        return (jsonify(error="Invalid password!"),400)
    return jsonify(**{**requested_user.to_dict(),**{"authToken":requested_user.authToken,"message":"Successfully logged in!"}})
@sock.route("/ws")
def websocket_endpoint(ws:flask_sock.Server):
    while True:
        msg:str = ws.receive()
        payload = json.loads(msg)
        if payload['opcode'] == 0:
            auth_token = payload['auth_token']
            user = db.authorize(auth_token)
            if not user:
                resp = {"status":0}
                ws.send(json.dumps(resp))
                ws.close(1000,"UNAUTHORIZED")
            resp = {"status":1,"username":user.username}
            ws.send(json.dumps())

app.run("127.0.0.1",5000)