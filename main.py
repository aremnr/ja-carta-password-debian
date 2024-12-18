from crypto_class import Crypto
from db_file import DB_FILE

crypto = Crypto("1234567890")

def create_db():
    user_info = crypto.create_user()
    user_db = DB_FILE(user_info[1].decode())
    user_db.write_db_data(user_info[2], [])
    return {"status": "created"}

def get_all():
    master, user_id = crypto.get_master_key_and_userID()
    user_db = DB_FILE(user_id.decode())
    salt, data = user_db.read_db_file()
    dec_data = crypto.decrypt_data(master, data, salt)
    dec_data = dec_data.decode() if not dec_data else bytes(dec_data).decode()
    return master, dec_data, user_db

def get_correct(domain: str):
    _, dec_data, _ = get_all()
    data_list = list(dec_data.split("\n"))
    for i in data_list:
        if domain in i[:i.find("\t")]:
            res = list(i.split('\t'))
            del res[0]
            return res
    raise Exception("Data don't found")


def add_data(domain: str, username: str, password: str):
    master_key, dec_data, db_file = get_all()
    new_data = dec_data + f"{domain}\t{username}\t{password}\n"
    salt, enc_data = crypto.encrypt_data(master_key, new_data)
    db_file.write_db_data(salt, enc_data)
    return {"status": "added"}

def key_change():
    _, dec_data, db_file = get_all()
    new_key = crypto.key_chage()
    salt, enc_data = crypto.encrypt_data(new_key, dec_data)
    db_file.write_db_data(salt, enc_data)
    return {"status": "key_changed"}

