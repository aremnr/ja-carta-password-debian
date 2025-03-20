from crypto_class import Crypto
from db_file import DB_FILE
import argparse

parser = argparse.ArgumentParser(description='ssss')
parser.add_argument("-m", "--mode", type=str, required=True, help="set mode")
parser.add_argument("-d", "--domain", type=str, help="set domain")
parser.add_argument("-u", "--username", type=str, help="set username")
parser.add_argument("-p", "--password", type=str, help="set password")

crypto = Crypto("12345678", lib_path="/usr/lib/librtpkcs11ecp.so")

def create_db():
    user_info = crypto.create_user()
    user_db = DB_FILE(str(user_info[0]))
    user_db.write_db_data(user_info[1], [])
    return {"status": "db_created"}

def get_all(key_return: bool = False):
    master, user_id = crypto.get_master_key_and_userID()
    user_db = DB_FILE(user_id.decode())
    salt, data = user_db.read_db_file()
    dec_data = crypto.decrypt_data(master, data, salt)
    dec_data = dec_data.decode() if not dec_data else bytes(dec_data).decode()
    if key_return:
        return master, dec_data, user_db
    else:
        return '', dec_data, user_db

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
    master_key, dec_data, db_file = get_all(key_return=True)
    new_data = dec_data + f"{domain}\t{username}\t{password}\n"
    salt, enc_data = crypto.encrypt_data(master_key, new_data)
    db_file.write_db_data(salt, enc_data)
    return {"status": "data_added"}

def key_change():
    _, dec_data, db_file = get_all()
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
        return(db_file.clear_db())

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

args = parser.parse_args()
if args.mode == "create database":
    print(create_db())
elif args.mode == "add data":
    print(add_data(args.domain, args.username, args.password))
elif args.mode == "get all":
    _, data, _ = get_all()
    print(list(data.replace("\x00", "").split()))
elif args.mode == "get correct":
    print(get_correct(args.domain))
elif args.mode == "change key":
    print(key_change())
elif args.mode == "delete data":
    delete_data(args.domain)
elif args.mode == "delete database":
    print(delete_db())
elif args.mode == "clear database":
    print(clear_db())
elif args.mode == "change data":
    print(change_data(args.domain, args.username, args.password))
elif args.mode == "check token":
    print(check_token())

