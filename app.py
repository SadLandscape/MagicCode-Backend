from flask.app import Flask,request
import sqlite3,secrets,flask


conn = sqlite3.connect("database.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS users ([uid] TEXT, [username] TEXT,[password_hash] TEXT,[email] TEXT,[notes] TEXT,[display_name] TEXT, [auth_token] TEXT)
""")
conn.commit()
cursor.execute("""
CREATE TABLE IF NOT EXISTS notes ([note_id] TEXT,[owner] TEXT,[team] TEXT,[note_text] TEXT,[settings] TEXT, [auth_code] TEXT)
""")
conn.commit()

def get_note(id:str):
    cursor.execute("""
    SELECT (note_id,owner,team,note_text,settings,auth_code) FROM notes
    WHERE note_id = ?
    """,(id,))
    note = cursor.fetchone()
    if not note:
        return None
    note_id,owner,team,note_text,settings,auth_code = note

app = Flask(__name__)

@app.route("/api/notes/<note_id:uuid>",methods=["GET","POST","PATCH"])
def get_note(note_id):
    if request.method == "GET":
        