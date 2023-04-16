import sqlite3,utils.classes
from ..objparser import obj_to_string,string_to_obj

class Database():
    def __init__(self) -> None:
        self.conn = sqlite3.connect("database.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS users ([uid] TEXT, [username] TEXT,[password_hash] TEXT,[email] TEXT,[notes] TEXT,[display_name] TEXT, [auth_token] TEXT)
        """)
        self.conn.commit()
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes ([note_id] TEXT,[owner] TEXT,[team] TEXT,[note_text] TEXT,[settings] TEXT, [auth_code] TEXT)
        """)
        self.conn.commit()

    def get_note(self,id:str):
        self.cursor.execute("""
        SELECT (note_id,owner,team,note_text,settings,auth_code) FROM notes
        WHERE note_id = ?
        """,(id,))
        note = self.cursor.fetchone()
        if not note:
            return None
        note_id,owner,team,note_text,settings,auth_code = note
        data = {"id":note_id,"owner":owner,"team":string_to_obj(team),"note_text":note_text,"settings":string_to_obj(settings),"auth_code":auth_code}
        return utils.classes.Note(data,self)
    def get_user(self,id:str):
        self.cursor.execute("""
        SELECT (uid,username,password_hash,email,notes,display_name,auth_token) FROM users
        WHERE uid = ?                    
        """,(id,))
        user = self.cursor.fetchone()
        if not user:
            return None
        uid,username,password_hash,email,notes,display_name,auth_token = user 
        data = {"id":uid,"username":username,"password_hash":password_hash,"email":email,"notes":string_to_obj(notes),"display_name":display_name,"auth_token":auth_token}
        return utils.classes.AuthenticatedUser(data,self)