from flask.app import Flask,request
import secrets,flask,flask_sock,json
from utils import database
from objparser import obj_to_string,string_to_obj
from flask_sock import Sock

app = Flask(__name__)
sock = Sock(app)
client_list = {}

"""
OPCODES:
0 - auth
1 - ping

PAYLOAD MODELS:
0 - {"opcode":0,"auth_token":"32 bit secrets token"} -> {"status":1/0,"username":"username","email":"email","notes":[],"display_name":"display name"}
1 - {"opcode":1} -> {"status":1}
"""

db = database.Database()
@app.route("/api/notes/<uuid:note_id>",methods=["GET","POST","PATCH"])
def get_note(note_id):
    if request.method == "GET":
        pass

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