import marshal
from base64 import b64encode,b64decode

def obj_to_string(object) -> str:
    return b64encode(marshal.dumps(object)).decode()

def string_to_obj(string):
    return marshal.loads(b64decode(string))