from crypto_class import Crypto
from db_file import DB_FILE
from fuzzywuzzy import process
import ast
from re import fullmatch

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
        master, user_db = get_init_data()
        _, enc_data = crypto.encrypt_data(master, "key_success", b'1111111111111111')
        hashed_check_data = crypto.return_hash(enc_data)
        user_db = DB_FILE(str(user_info[0]))
        user_db.init_db(hashed_check_data)
        return {"status": "db_created"}

def get_all():
    try:
        master, user_db = get_init_data()
        domains, _, _ = user_db.read_db_file()
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

def get_correct(domain: str = '', id: int = 0, master: b"" = b"", user_db: DB_FILE = ""):
    try:
        if master == b"" and user_db == "":
            master, user_db = get_init_data()
        elif master != b"" and user_db == "":
            _, user_db = get_init_data()
        elif master != b"" and user_db != "":
            pass
    except:
        create_db()
        return get_correct(domain, id)
    domains, passwds, check_text = user_db.read_db_file()
    if not checker(check_text):
        return {"status": "key_not_accepted"}
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
    try:   
        master, user_db = get_init_data()
        domains, passwords, check_text = user_db.read_db_file()
    except BaseException as e:
        print(e)
        create_db()
        return add_data(domain, username, password)
    if not checker(check_text):
        return {"status": "key_not_accepted"}
    salt, enc_data = crypto.encrypt_data(master, f"{username}\t{password}")
    domains.append(domain)
    line = f"{domain}\t{salt}{enc_data}\n"
    passwords.append(line.encode())
    user_db.write_db_data(domains, passwords, check_text)
    return {"status": "data_added"}

def key_change():
    try:
        master1, db_file1 = get_init_data()
        domains, _, check_text = db_file1.read_db_file()
    except:
        create_db()
        return key_change()
    passwords_count = get_all()
    if passwords_count == 0:
        crypto.key_change()
        return {"status": "data_key_changed"}
    if not checker(check_text):
        return {"status": "key_not_accepted"}
    crypto.delete_user()
    create_db()
    for i in range(passwords_count):
        data_to_add = []
        data = get_correct(id=i, master=master1, user_db=db_file1)
        data_to_add.extend(data)
        add_data(data_to_add[0], data_to_add[1], data_to_add[2])
    db_file1.delete_db()
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
    try:
        _, db = get_init_data()
        domains, passwords, check_text = db.read_db_file()
    except:
        create_db()
        return delete_data(domain)
    if not checker(check_text):
        return {"status": "key_not_accepted"}
    try:
        id = domains.index(domain)
    except ValueError:
        return {"status": "data_not_found"}
    passwords.pop(id)
    domains.pop(id)
    db.write_db_data(domains, passwords, check_text)
    return {"status": "data_deleted"}

def change_data(domain: str, username: str, password: str):
    if fullmatch(r"^[a-z][^\W_]{0,150}$", username) == None or \
        fullmatch(r"^(?=[^a-z]*[a-z])(?=\D*\d)[^:&./\\~\s]{0,150}$", password) == None:
        return {"status": "data_not_allowed"}
    try:
        master, db = get_init_data()
        domains, passwords, check_text = db.read_db_file()
    except:
        create_db()
        return change_data(domain, username, password)
    try:
        id = domains.index(domain)
    except ValueError:
        return {"status": "data_not_found"}
    if not checker(check_text):
        return {"status": "key_not_accepted"}
    salt, enc_data = crypto.encrypt_data(master, f"{username}\t{password}")
    line = f"{domain}\t{salt}{enc_data}\n"
    passwords[id] = line.encode()
    db.write_db_data(domains, passwords, check_text)
    return {"status": "data_changed"}

def get_fuzzy(domain):
    try:
        _, db = get_init_data()
        domains, _, check_text = db.read_db_file()
    except:
        create_db()
        return get_fuzzy(domain)
    if not checker(check_text):
        return {"status": "key_not_accepted"}
    matches = process.extract(domain, domains, limit=15)
    r_data = []
    for match, _ in matches:
        data = get_correct(match)
        r_data.extend([*data])
    return r_data

def checker(check_text):
    
    if crypto.check_text and check_text==crypto.check_text:
        return True
    try:
        master, db_file = get_init_data()
    except:
        create_db()
        return checker
    _, _, check_text = db_file.read_db_file()
    _, enc_text = crypto.encrypt_data(master, "key_success", b'1111111111111111')
    hashed_text = crypto.return_hash(enc_text)
    if hashed_text == check_text:
        crypto.check_text = check_text
        return True
    return False
    