import PyKCS11
import PyKCS11.LowLevel
import os
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class TempClass:
    def __init__(self, user_id, master_key):
        self.user_id = user_id
        self.master_key = master_key


class Crypto:
    def __init__(self, pin: str, slot: int = 0, lib_path: str = "/usr/lib/libjcPKCS11-2.so"):
        """
        pin         (required): pin for connect
        slot        (optional): slot for session
        lib_path    (optional): path of pkcs11 library
        """
        self.pin = pin
        self.slot = slot
        self.lib_path = lib_path

    def __init_lib(self):
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(self.lib_path)
        self.pkcs11 = pkcs11
        return pkcs11
    
    def __session_create(self):
        slot = self.slot if self.slot != 0 else self.pkcs11.getSlotList(tokenPresent=True)[0]
        session = self.pkcs11.openSession(slot, PyKCS11.LowLevel.CKF_SERIAL_SESSION | PyKCS11.LowLevel.CKF_RW_SESSION)
        session.login(self.pin)
        self.session = session
        self.slot= slot
        return session

    def __session_end(self):
        self.session.logout()
        self.session.closeSession()
        return True

    def __mechanism_set(self):
        self.mechanism = PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_GOST28147_ECB, [])
        return self.mechanism
     
    def __init_crypto_context(self):
        self.__init_lib()
        self.__session_create()
        self.__mechanism_set()
    
    def __generate_salt(self):
        salt = os.urandom(24)
        return salt

    def __pad_data(self, data, block_size=8): 
        padding_len = block_size - (len(data) % block_size)
        return data + bytes([0] * padding_len)

    def __generate_key(self, master_key: bytes, salt: bytes = b""):
        salt = self.__generate_salt() if salt == b"" else salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )

        key_bytes = kdf.derive(master_key)
        gost_params = b"\x06\x07\x2a\x85\x03\x02\x02\x1f\x00"
        
        key_template = [
            (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_SECRET_KEY),   
            (PyKCS11.LowLevel.CKA_KEY_TYPE, PyKCS11.LowLevel.CKK_GOST28147),       
            (PyKCS11.LowLevel.CKA_VALUE, key_bytes),
            (PyKCS11.LowLevel.CKA_ENCRYPT, PyKCS11.LowLevel.CK_TRUE),  
            (PyKCS11.LowLevel.CKA_DECRYPT, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_LABEL, "Very Very Secret key"),
            (PyKCS11.LowLevel.CKA_GOST28147_PARAMS, gost_params),
        ]
        key = self.session.createObject(key_template)

        return salt, key

    def encrypt_data(self, master_key: bytes, data: str):
        self.__init_crypto_context()
        salt, key = self.__generate_key(master_key)
        enc_text = self.session.encrypt(key, self.__pad_data(data.encode()), self.mechanism)
        self.session.destroyObject(key)
        self.__session_end()
        return salt, enc_text
    
    def decrypt_data(self, master_key: bytes, data, salt: bytes):
        if not data: return b''
        self.__init_crypto_context()
        __, key = self.__generate_key(master_key, salt)
        dec_data = self.session.decrypt(key, data, self.mechanism)
        self.session.destroyObject(key)
        self.__session_end()
        return dec_data

    def __master_key_generate(self):
        master_key = os.urandom(32)
        # master_key_template = [
        #     (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_DATA),
        #     (PyKCS11.LowLevel.CKA_VALUE, master_key),
        #     (PyKCS11.LowLevel.CKA_TOKEN, PyKCS11.LowLevel.CK_TRUE),
        #     (PyKCS11.LowLevel.CKA_LABEL, "Master Key"),
        #     (PyKCS11.LowLevel.CKA_PRIVATE, PyKCS11.LowLevel.CK_TRUE)
        # ]
        # master = self.session.createObject(master_key_template)
        with open(f"./temp", "wb") as f:
            f.write(master_key)
        return master_key

    def __generate_user_id(self):
        user_id = uuid.uuid4()
        # user_id_template = [
        #     (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_DATA),
        #     (PyKCS11.LowLevel.CKA_VALUE, str(user_id).encode()),
        #     (PyKCS11.LowLevel.CKA_TOKEN, PyKCS11.LowLevel.CK_TRUE),
        #     (PyKCS11.LowLevel.CKA_LABEL, "User ID"),
        # ]
        # user_id = self.session.createObject(user_id_template)
        with open(f"./temp", "ab") as f:
            f.write(str(user_id).encode())
        return str(user_id).encode()

    def create_user(self):
        self.__init_crypto_context()
        # token = self.pkcs11.getTokenInfo(self.slot)
        # freepr = token.ulFreePrivateMemory
        # freepb = token.ulTotalPrivateMemory
        # print(freepb, freepr)
        master_key = self.__master_key_generate()
        user_id = self.__generate_user_id()
        salt, key = self.__generate_key(master_key)
        self.session.destroyObject(key)
        # self.session.destroyObject(user_id)
        # self.session.destroyObject(master_key)
        self.__session_end()
        return [master_key, user_id, salt, key]

    def get_master_key_and_userID(self):
        #self.__init_crypto_context()
        #
        # objects = self.session.findObjects([
        #         (PyKCS11.LowLevel.CKA_LABEL, "Master Key")
        # ])

        # for obj in objects:
        #     attr = self.session.getAttributeValue(obj, [PyKCS11.LowLevel.CKA_VALUE])
        #     master_key = attr[0]

        # objects = self.session.findObjects([
        #         (PyKCS11.LowLevel.CKA_LABEL, "User ID")
        # ])

        # for obj in objects:
        #     attr = self.session.getAttributeValue(obj, [PyKCS11.LowLevel.CKA_VALUE])
        #     user_id = attr[0]
        # self.__session_end()
        with open("./temp", "rb") as f:
            data = f.read()
            master_key, user_id = data[:32], data[32:]
        return master_key, user_id

    def key_chage(self):
        #self.__init_crypto_context()
        #
        # master_key = self.session.findObjects([
        #         (PyKCS11.LowLevel.CKA_LABEL, "Master Key")
        # ])
        # self.session.destroyObject(master_key)
        # master_key = self.__master_key_generate()
        # return new_key

        _, user_id = self.get_master_key_and_userID()
        new_key = self.__master_key_generate()
        with open(f"./temp", "ab") as f:
            f.write(user_id)
        
        return new_key
    
