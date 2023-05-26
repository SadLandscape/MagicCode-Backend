from flask.app import Flask, request
from flask import  jsonify
import secrets, flask_sock, json, hashlib, uuid
from flask_sqlalchemy import SQLAlchemy
from flask_sock import Sock
from functools import wraps

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.sqlite3"
db = SQLAlchemy(app)
sock = Sock(app)
client_list = {}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not 'authToken' in request.headers:
            return (jsonify(error="Unauthorized"), 401)
        auth_token = request.headers['authToken']
        c_user = db.session.query(User).filter_by(authToken=auth_token).first()
        if not c_user:
            return (jsonify(error="Unauthorized"), 401)
        return f(*args, **kwargs)
    return decorated_function

class Member(db.Model):
    __tablename__ = "members"
    id = db.Column(db.String, primary_key=True)
    user_id = db.Column(db.String(), db.ForeignKey('users.id'), nullable=False)
    board_id = db.Column(db.String(), db.ForeignKey('boards.id'), nullable=False)
    can_edit = db.Column(db.Boolean, default=False)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    authToken = db.Column(db.String(), nullable=False)
    display_name = db.Column(db.String(40), nullable=False)
    notes = db.relationship('Note', backref='author')
    categories = db.relationship('Category', backref='author')
    owned_boards = db.relationship('Board', backref='owner')

    def to_dict(self, show_notes: bool = True):
        data = {
            "id": self.id,
            "username": self.username,
            "displayName": self.display_name,
            "email": self.email
        }
        if show_notes:
            data.update({
                "boards":[board.to_dict(user_id=self.id) for board in ([member.board for member in db.session.query(Member).filter_by(user_id=self.id).all() if not member.board in self.owned_boards]+self.owned_boards)]
            })
        return data


class Note(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.String(), primary_key=True)
    description = db.Column(db.Text, nullable=True)
    title = db.Column(db.String, nullable=False)
    access_code = db.Column(db.String, nullable=False)
    author_id = db.Column(db.String(), db.ForeignKey('users.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'))

    def to_dict(self, can_share=True, show_owner=False):
        data = {"Id": self.id, "title": self.title, "text": self.description,"category":self.category.to_dict(False)}
        if can_share:
            data.update({"shareToken": self.access_code})
        if show_owner:
            data.update({"author": self.author.to_dict(False)})
        return data


class Category(db.Model):
    __tablename__ = "categories"
    id = db.Column(db.String, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    notes = db.relationship('Note', backref='category')
    author_id = db.Column(db.String(), db.ForeignKey('users.id'))
    board_id = db.Column(db.Integer, db.ForeignKey('boards.id'))

    def to_dict(self,show_notes=True):
        data = {"Id": self.id, "title": self.name,"notes":[]}
        if show_notes:
            notes = [note.to_dict(can_share=False,show_owner=True) for note in self.notes]
            data.update({"notes":notes})
        author = db.session.query(User).filter_by(id=self.author_id).first().to_dict(show_notes=False)
        data.update({"author":author})
        return data

class Board(db.Model):
    __tablename__ = "boards"
    id = db.Column(db.String, primary_key=True)
    owner_id = db.Column(db.String(), db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(),nullable=False)
    categories = db.relationship('Category', backref='board')
    members = db.relationship('Member', backref='board')
    tokens = db.relationship("ShareToken",backref="board")
    def to_dict(self,show_tokens=True,user_id=""):
        data = {"Id": self.id, "author": db.session.query(User).filter_by(id=self.owner_id).first().to_dict(show_notes=False),"title":self.title}
        categories = [category.to_dict() for category in self.categories]
        if show_tokens:
            tokens = [token.to_dict(False) for token in self.tokens]
            data.update({"tokens":tokens})
        member = db.session.query(Member).filter_by(user_id=user_id,board_id=self.id).first()
        data.update({"canDelete":user_id==self.owner_id,"canEdit":member.can_edit if member else user_id == self.owner_id})
        data.update({"categories": categories})
        return data

class ShareToken(db.Model):
    __tablename__ = "sharetokens"
    id = db.Column(db.String,primary_key=True)
    owner_id = db.Column(db.String,db.ForeignKey("users.id"),nullable=False)
    board_id = db.Column(db.String,db.ForeignKey("boards.id"),nullable=False)
    can_write = db.Column(db.Boolean,nullable=False)
    invites_used = db.Column(db.Integer,default=0)
    def to_dict(self,show_board=True):
        data = {"Id":self.id,"boardId":self.board_id,"author":db.session.query(User).filter_by(id=self.owner_id).first().to_dict(show_notes=False),"can_write":self.can_write,"uses":self.invites_used}
        if show_board:
            data.update({"board":self.board.to_dict(False)})
        return data
with app.app_context():
    db.create_all()

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

@app.route("/api/tokens/generate",methods=["POST"])
@login_required
def generate_token():
    if request.method == "POST":
        auth_token = request.headers['authToken']
        board_id = request.json['boardId']
        can_write = request.json['can_write']
        c_user = db.session.query(User).filter_by(authToken=auth_token).first()
        if not c_user:
            return (jsonify(error="Unauthorized"), 401)
        board = db.session.query(Board).filter_by(id=board_id).first()
        if not board:
            return (jsonify(error="Board not found!"),404)
        if board.owner_id != c_user.id:
            return (jsonify(error="You aren't permitted to delete this!"),401)
        new_share_token = ShareToken(id=str(uuid.uuid4()),owner_id=c_user.id,board_id=board.id,can_write=can_write,invites_used=0)
        db.session.add(new_share_token)
        db.session.commit()
        return jsonify(**new_share_token.to_dict(),message="Successfully created token!")

@app.route("/api/boards/<board_id>",methods=["GET","DELETE"])
@login_required
def delete_board(board_id):
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    board = db.session.query(Board).filter_by(id=board_id).first()
    if not board:
        return (jsonify(error="Board not found!"),404)
    if request.method == "DELETE":
        if board.owner_id != c_user.id:
            return (jsonify(error="You aren't permitted to delete this!"),401)
        [db.session.delete(user) for user in board.members]
        [db.session.delete(token) for token in board.tokens]
        db.session.delete(board)
        db.session.commit()
        return jsonify(message="Successfully deleted board!")
    return jsonify(**board.to_dict(user_id=c_user.id),message="Successfully fetched board!")

@app.route("/api/boards/<board_id>/leave",methods=["POST"])
@login_required
def leave_board(board_id):
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    board = db.session.query(Board).filter_by(id=board_id).first()
    if not board:
        return (jsonify(error="Board not found!"),404)
    [db.session.delete(user) for user in board.members if user.user_id == c_user.id and user.board_id == board_id]
    db.session.commit()
    return jsonify(message="Successfully left the board!")

@app.route("/api/notes/<note_id>/updateSettings",methods=["POST"])
@login_required
def update_settings(note_id):
    auth_token = request.headers['authToken']
    title = request.json['title']
    category_id = request.json['categoryId']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    note = db.session.query(Note).filter_by(id=note_id).first()
    if not note:
        return (jsonify(error="Note not found!"),404)
    member = db.session.query(Member).filter_by(user_id=c_user.id,board_id=note.category.board.id).first()
    if (member and not member.can_edit) or note.category.board.owner_id !=c_user.id:
        return (jsonify(error="You aren't permitted to perform this action!"),403)
    category = db.session.query(Category).filter_by(id=category_id).first()
    if not category:
        return (jsonify(error="Category doesn't exist!"),404)
    note.category_id = category_id
    note.category = category
    note.title = title
    db.session.commit()
    return jsonify(message='Successfully saved the changes!')

@app.route("/api/boards/<board_id>/tokens/<id>/delete",methods=["DELETE"])
@login_required
def delete_token(board_id,id):
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    board = db.session.query(Board).filter_by(id=board_id).first()
    if not board:
        return (jsonify(error="Board not found!"),404)
    if board.owner_id != c_user.id:
        return (jsonify(error="You aren't permitted to delete this!"),401)
    token = db.session.query(ShareToken).filter_by(id=id).first()
    if not token:
        return (jsonify(error="Token not found"),404)
    db.session.delete(token)
    db.session.commit()
    return jsonify(message="Successfully deleted token!")

@app.route("/api/boards/join",methods=['POST'])
@login_required
def join_board():
    auth_token = request.headers['authToken']
    sharetoken = request.json['shareToken']
    token = db.session.query(ShareToken).filter_by(id=sharetoken).first()
    if not token:
        return (jsonify(error="QR not valid!"),404)
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    token.invites_used +=1
    board = token.board
    if db.session.query(Member).filter_by(user_id=c_user.id,board_id=board.id).first():
        return (jsonify(error="Already joined"),400)
    member = Member(id=uuid.uuid4().__str__(),user_id=c_user.id,board_id=board.id,can_edit=token.can_write)
    board.members.append(member)
    db.session.add(member)
    db.session.commit()
    return jsonify(message=f"Successfully joined board \"{board.title}\"")
@app.route("/api/boards/<board_id>/tokens",methods=["GET"])
@login_required
def get_tokens(board_id):
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    board = db.session.query(Board).filter_by(id=board_id).first()
    if not board:
        return (jsonify(error="Board not found!"),404)
    if board.owner_id != c_user.id:
        return (jsonify(error="You aren't permitted to delete this!"),401)
    return jsonify(tokens=board.to_dict(True)['tokens'])

@app.route("/api/notes/<note_id>", methods=["GET", "PATCH","DELETE"])
@login_required
def get_note(note_id):
    if request.method == "GET":
        note = db.session.query(Note).filter_by(id=note_id).first()
        if not note:
            return (jsonify(valid=False, error="Note not found!"), 400)
        return jsonify(**note.to_dict(show_owner=True))
    if request.method == "PATCH":
        note = db.session.query(Note).filter_by(id=note_id).first()
        if not note:
            return (jsonify(valid=False, error="Note not found!"), 400)
        newdata = request.json['text']
        note.description = newdata
        db.session.commit()
        return jsonify(valid=True, message="Successfully saved changes!")
    if request.method == "DELETE":
        auth_token = request.headers['authToken']
        c_user = db.session.query(User).filter_by(authToken=auth_token).first()
        if not c_user:
            return (jsonify(error="Unauthorized"), 401)
        note = db.session.query(Note).filter_by(id=note_id).first()
        if note.author_id != c_user.id:
            return (jsonify(error="You aren't permitted to delete this!"),401)
        db.session.delete(note)
        db.session.commit()
        return jsonify(message="Successfully deleted note!")

@app.route("/api/usernames/<username>", methods=["GET"])
def check_username(username):
    return jsonify(available=not db.session.query(User).filter_by(
        username=username).first())


@app.route("/api/auth/register", methods=["POST"])
def register():
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']
    if db.session.query(User).filter_by(username=username).first():
        response = {"error": "Username already exists!"}
        return (jsonify(**response), 400)
    if db.session.query(User).filter_by(email=email).first():
        return (jsonify(error="This email is already registered!"), 400)
    user = User(username=username,
                email=email,
                password=hashlib.md5(password.encode()).hexdigest(),
                id=uuid.uuid4().__str__(),
                display_name=username,
                authToken=secrets.token_hex(32))
    db.session.add(user)
    db.session.commit()
    return jsonify(**{
        "authToken": user.authToken,
        "message": "Successfull registered!"
    })


@app.route("/api/auth/currentUser", methods=["GET"])
def get_current_user():
    pass

@app.route("/api/boards/getBoards",methods=["GET"])
@login_required
def get_boards():
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    return jsonify(boards=c_user.to_dict()['boards'])

@app.route("/api/boards/create",methods=["POST"])
@login_required
def create_board():
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    data = request.json
    board = Board(id=str(uuid.uuid4()),title=data['title'],owner_id=c_user.id)
    member = Member(id=str(uuid.uuid4()),board_id=board.id,user_id=c_user.id,can_edit=True)
    db.session.add_all([board,member])
    db.session.commit()
    return jsonify(boards=board.to_dict(),message="Successsfully created the board!")

@app.route("/api/user/notes", methods=["GET"])
@login_required
def get_notes():
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    return jsonify(notes=c_user.to_dict()['notes'])

@app.route("/api/boards/<board_id>/categories",methods=["GET"])
@login_required
def get_categories(board_id):
    board = db.session.query(Board).filter_by(id=board_id).first()
    if not board:
        return (jsonify(error="Board not found!"),404)
    return jsonify(categories=[category.to_dict() for category in board.categories])



@app.route("/api/categories/<category_id>",methods=["DELETE"])
@login_required
def delete_category(category_id):
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    category = db.session.query(Category).filter_by(id=category_id).first()
    if not category:
        return (jsonify(error="Category not found!"),404)
    if category.author_id != c_user.id or category.board.owner_id != c_user.id:
        return (jsonify(error="You aren't permitted to delete this!"),401)
    db.session.delete(category)
    db.session.commit()
    return jsonify(message="Successfully deleted category!")

@app.route("/api/boards/<board_id>/categories/create",methods=["POST"])
@login_required
def create_category(board_id):
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    board = db.session.query(Board).filter_by(id=board_id).first()
    if not board:
        return (jsonify(error="Board not found!"),404)
    data = request.json
    new_category = Category(id=str(uuid.uuid4()),name=data['title'],author_id=c_user.id,board_id=board_id)
    db.session.add(new_category)
    db.session.commit()
    return jsonify(category=new_category.to_dict(),message=f"Successfully created category \"{data['title']}\"")

@app.route("/api/notes/createNote", methods=["POST"])
@login_required
def new_note():
    auth_token = request.headers['authToken']
    c_user = db.session.query(User).filter_by(authToken=auth_token).first()
    data = request.json
    title = data['title']
    text = data['text']
    category_id = data['category_id']
    if not db.session.query(Category).filter_by(id=category_id).first():
        return (jsonify(error="Category not found!"),404)
    note = Note(id=str(uuid.uuid4()),
                title=title,
                description=text,
                author_id=c_user.id,
                access_code=str(uuid.uuid4()),
                category_id=category_id)
    db.session.add(note)
    db.session.commit()
    return jsonify(status=True,
                   message=f'Successfully created note "{title}"')


@app.route("/api/auth/checkAuth", methods=["GET"])
def check_auth():
    auth_token = request.headers['authToken']
    return jsonify(valid=bool(
        db.session.query(User).filter_by(authToken=auth_token).first()),
                   message="Successfully logged in")


@app.route("/api/auth/login", methods=["POST"])
def login():
    email = request.json['email']
    password = request.json['password']
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    requested_user = db.session.query(User).filter_by(email=email).first()
    if not requested_user:
        return (jsonify(
            error="No such user with the given email address exists!"), 400)
    if not pw_hash == requested_user.password:
        return (jsonify(error="Invalid password!"), 400)
    return jsonify(
        **{
            "authToken": requested_user.authToken,
            "message": "Successfully logged in!"
        })


@sock.route("/ws")
def websocket_endpoint(ws: flask_sock.Server):
    while True:
        msg: str = ws.receive()
        payload = json.loads(msg)
        if payload['opcode'] == 0:
            auth_token = payload['auth_token']
            user = db.authorize(auth_token)
            if not user:
                resp = {"status": 0}
                ws.send(json.dumps(resp))
                ws.close(1000, "UNAUTHORIZED")
            resp = {"status": 1, "username": user.username}
            ws.send(json.dumps())


app.run("0.0.0.0", 5000)