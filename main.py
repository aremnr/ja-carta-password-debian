from crypto_class import Crypto
from db_file import DB_FILE
from fuzzywuzzy import process

crypto = Crypto("12345678", lib_path="/usr/lib/librtpkcs11ecp.so")

def create_db():
    user_info = crypto.create_user()
    user_db = DB_FILE(str(user_info[0]))
    user_db.write_db_data(user_info[1], [])
    return {"status": "db_created"}

def get_all(key_return: bool = False):
    try:
        master, user_id = crypto.get_master_key_and_userID()
        user_db = DB_FILE(user_id.decode())
        salt, data = user_db.read_db_file()
    except: 
        create_db()
        return get_all()
    dec_data = crypto.decrypt_data(master, data, salt)
    dec_data = dec_data.decode() if not dec_data else bytes(dec_data).decode()
    if key_return:
        return master, dec_data, user_db
    else:
        return '', dec_data, user_db
    

def get_correct(domain: str):
    _, dec_data, _ = get_all()
    data_list = list(dec_data.replace("\x00", "").split("\n"))
    for i in data_list:
        if domain == i[:i.find("\t")]:
            res = list(i.split('\t'))
            return res
    return {}

def add_data(domain: str, username: str, password: str):
    master_key, dec_data, db_file = get_all(key_return=True)
    new_data = dec_data + f"{domain}\t{username}\t{password}\n"
    salt, enc_data = crypto.encrypt_data(master_key, new_data)
    db_file.write_db_data(salt, enc_data)
    return {"status": "data_added"}

def key_change():
    _, dec_data, db_file = get_all()
    if dec_data == '':
        new_key = crypto.key_change()
        return {"status": "data_key_changed"}
    new_key = crypto.key_change()
    salt, enc_data = crypto.encrypt_data(new_key, dec_data)
    db_file.write_db_data(salt, enc_data)
    return {"status": "data_key_changed"}

def clear_db():
    _, _, db_file = get_all()
    return(db_file.clear_db())

def delete_db():
    _, _, db_file = get_all()
    if crypto.delete_user()["status"] == "data_deleted":
        return(db_file.delete_db())

def check_token():
    return crypto.check_token()

def delete_data(domain: str):
    master_key, data, db_file = get_all(key_return=True)
    data = list(data.replace("\x00", "").split())
    index = data.index(domain)
    data.pop(index)
    data.pop(index)
    data.pop(index)
    db_file.clear_db()
    if data:
        salt, enc_data = crypto.encrypt_data(master_key, '\t'.join(data))
        db_file.write_db_data(salt, enc_data)
    return {"status": "data_deleted"}

def change_data(domain: str, username: str, password: str):
    master_key, data, db_file = get_all(key_return=True)
    data = list(data.replace("\x00", "").split())
    index = data.index(domain)
    data[index+1] = username
    data[index+2] = password
    db_file.clear_db()
    salt, enc_data = crypto.encrypt_data(master_key, '\t'.join(data))
    db_file.write_db_data(salt, enc_data)
    return {"status": "data_changed"}

def get_fuzzy(domain):
    _, dec_data, _ = get_all()
    data = list(dec_data.replace("\x00", "").split())
    domains = data[::3]
    matches = process.extract(domain, domains, limit=15)
    r_data = []
    for match, _ in matches:
        data = get_correct(match)
        r_data.extend([*data])
    return r_data
