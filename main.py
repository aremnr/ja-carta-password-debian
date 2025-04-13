from crypto_class import Crypto
from db_file import DB_FILE
from fuzzywuzzy import process
import ast
from re import fullmatch, search

crypto = Crypto("12345678", lib_path="/usr/lib/librtpkcs11ecp.so")

def get_init_data():
    master, user_id = crypto.get_master_key_and_userID()
    user_db = DB_FILE(user_id.decode()) 
    return master, user_db


def create_db():
    try:
        get_init_data()
        return {"status": "token_have_another_db"}
    except:
        user_info = crypto.create_user()
        user_db = DB_FILE(str(user_info[0]))
        user_db.init_db()
        return {"status": "db_created"}

def get_all():
    try:
        master, user_db = get_init_data()
        domains, _ = user_db.read_db_file()
    except: 
        create_db()
        return get_all()
    r_data = len(domains)
    # for i in passwords:
    #     a = i.decode().strip("\n").split("\t")
    #     r_data.append(a[0])
    #     a[1] = ast.literal_eval(a[1])
    #     password = crypto.decrypt_data(master, a[1][16:], a[1][:16]).decode().replace("\x00", "")
    #     r_data.extend(password.split("\t"))
    return r_data    

def get_correct(domain: str = '', id: int = 0):
    master, user_db = get_init_data()
    domains, passwds = user_db.read_db_file()
    try:
        if domain != '':
            id = domains.index(domain)
        test = domains[id]
    except (ValueError, IndexError):
        return {}
    passwd = passwds[id]
    r_data = []
    a = passwd.decode().strip("\n").split("\t")
    r_data.append(a[0])
    a[1] = ast.literal_eval(a[1])
    password = crypto.decrypt_data(master, a[1][16:], a[1][:16]).decode().replace("\x00", "")
    r_data.extend(password.split("\t"))
    return r_data

def add_data(domain: str, username: str, password: str):
    if fullmatch(r"^[a-z][^\W_]{0,150}$", username) == None or \
        fullmatch(r"^(?=[^a-z]*[a-z])(?=\D*\d)[^:&./\\~\s]{0,150}$", password) == None:
        return {"status": "data_not_allowed"}        
    master, user_db = get_init_data()
    salt, enc_data = crypto.encrypt_data(master, f"{username}\t{password}")
    domains, passwords = user_db.read_db_file()
    domains.append(domain)
    line = f"{domain}\t{salt}{enc_data}\n"
    passwords.append(line.encode())
    user_db.write_db_data(domains, passwords)
    return {"status": "data_added"}

def key_change():
    _, db_file = get_init_data()
    domains, passwords = db_file.read_db_file()
    if passwords == []:
        crypto.key_change()
        return {"status": "data_key_changed"}
    dec_data = get_all()
    new_data = []
    new_key = crypto.key_change()
    for i in range(0, len(dec_data), 3):
        salt, enc_data = crypto.encrypt_data(new_key, f"{dec_data[i+1]}\t{dec_data[i+2]}")
        line = f"{dec_data[i]}\t{salt}{enc_data}\n"
        new_data.append(line.encode())
    db_file.write_db_data(domains, new_data)
    return {"status": "data_key_changed"}

def clear_db():
    _, db_file = get_init_data()
    return(db_file.clear_db())

def delete_db():
    _, db_file = get_init_data()
    if crypto.delete_user()["status"] == "data_deleted":
        return(db_file.delete_db())

def check_token():
    return crypto.check_token()

def delete_data(domain: str):
    _, db = get_init_data()
    domains, passwords = db.read_db_file()
    try:
        id = domains.index(domain)
    except ValueError:
        return {"status": "data_not_found"}
    passwords.pop(id)
    domains.pop(id)
    db.write_db_data(domains, passwords)
    return {"status": "data_deleted"}

def change_data(domain: str, username: str, password: str):
    if fullmatch(r"^[a-z][^\W_]{0,150}$", username) == None or \
        fullmatch(r"^(?=[^a-z]*[a-z])(?=\D*\d)[^:&./\\~\s]{0,150}$", password) == None:
        return {"status": "data_not_allowed"}
    master, db = get_init_data()
    domains, passwords = db.read_db_file()
    try:
        id = domains.index(domain)
    except ValueError:
        return {"status": "data_not_found"}
    salt, enc_data = crypto.encrypt_data(master, f"{username}\t{password}")
    line = f"{domain}\t{salt}{enc_data}\n"
    passwords[id] = line.encode()
    db.write_db_data(domains, passwords)
    return {"status": "data_changed"}

def get_fuzzy(domain):
    _, db = get_init_data()
    domains, _ = db.read_db_file()
    matches = process.extract(domain, domains, limit=15)
    r_data = []
    for match, _ in matches:
        data = get_correct(match)
        r_data.extend([*data])
    return r_data
