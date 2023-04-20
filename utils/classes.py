import utils

class Note():
    def __init__(self,data:dict,db:utils.database.Database,uid:str) -> None:
        self.data = data
        self.owner:str = data['owner']
        self.id:str = data['id']
        self.can_delete = uid == self.owner
        self.note_text:str = data['note_text']
        self.users:list = data['team']
        self.users = []
        self.settings:dict = data['settigns']
        self.auth_code:str = data['auth_code']
        print(self.__dict__)
    def back_to_json(self):
        return self.__dict__
class PartialUser():
    def __init__(self,data:dict,db:utils.database.Database) -> None:
        self.data = data 
        self.uid:str = data['uid']
        self.username:str = data['username']

    def back_to_json(self):
        return self.data
class AuthenticatedUser():
    def __init__(self,data:dict,db:utils.database.Database) -> None:
        self.data = data
        self.uid:str = data['uid']
        self.email:str = data['email']
        self.password_hash:str = data['password_hash']
        self.token:str = data['token']
        self.username:str = data['username']
        self.display_name:str = data['username']
        
    def back_to_json(self):
        return self.data
class UserSettings():
    def __init__(self,data:dict) -> None:
        self.data = data
        self.enable_invites:bool = data['invite_privacy']
        
    def back_to_json(self):
        return self.data
class NoteSettngs():
    def __init__(self,data:dict,db:utils.database.Database) -> None:
        self.data = data
        self.auto_delete:int = data['auto_delete']
        
    def back_to_json(self):
        return self.data