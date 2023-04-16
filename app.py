from flask.app import Flask,request
import secrets,flask,utils.database as database
from objparser import obj_to_string,string_to_obj

app = Flask(__name__)
db = database.Database()
@app.route("/api/notes/<note_id:uuid>",methods=["GET","POST","PATCH"])
def get_note(note_id):
    if request.method == "GET":
        pass