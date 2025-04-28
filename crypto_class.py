import PyKCS11
import PyKCS11.LowLevel
import os
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Crypto:
    def __init__(self, pin: str, slot: int = 0, lib_path: str = "/usr/lib/libjcPKCS11-2.so"):
        """
        pin         (required): pin for connect\n
        slot        (optional): slot for session\n
        lib_path    (optional): path of pkcs11 library
        """
        self.pin = pin
        self.slot = slot
        self.lib_path = lib_path
        self.check_text = b""

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

        self.mechanism = PyKCS11.Mechanism(PyKCS11.LowLevel.CKM_GOST28147_ECB, None)
        return self.mechanism
     
    def __init_crypto_context(self):
        self.__init_lib()
        self.__session_create()
        self.__mechanism_set()
    
    def __generate_salt(self):
        salt = os.urandom(16)
        return salt

    def __pad_data(self, data, block_size=8): 
        if len(data)%8 == 0: return data
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
            (PyKCS11.LowLevel.CKA_LABEL, "Secret key"),
            #(PyKCS11.LowLevel.CKA_GOST28147_PARAMS, gost_params),
        ]
        key = self.session.createObject(key_template)

        return salt, key

    def encrypt_data(self, master_key: bytes, data: str, salt: bytes = b""):
        self.__init_crypto_context()
        salt, key = self.__generate_key(master_key, salt)
        data_2 = self.__pad_data(data.encode())
        enc_text = b""
        while len(data_2) > 32:
            enc_text += bytes(self.session.encrypt(key, data_2[0:32],  self.mechanism))
            data_2 = data_2[32:]
        enc_text += bytes(self.session.encrypt(key, data_2,  self.mechanism))
        self.session.destroyObject(key)
        self.__session_end()
        return salt, enc_text
    
    def decrypt_data(self, master_key: bytes, data, salt: bytes):
        if not data: return b''
        self.__init_crypto_context()
        __, key = self.__generate_key(master_key, salt)
        dec_data = b""
        while len(data) > 32:
            dec_data += bytes(self.session.decrypt(key, data[0:32], self.mechanism))
            data = data[32:]
        dec_data += bytes(self.session.decrypt(key, data[0:32], self.mechanism))
        self.session.destroyObject(key)
        self.__session_end()
        return dec_data

    def __master_key_generate(self):
        master_key = os.urandom(32)
        master_key_template = [
            (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_DATA),
            (PyKCS11.LowLevel.CKA_VALUE, master_key),
            (PyKCS11.LowLevel.CKA_TOKEN, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_LABEL, "Master Key"),
            (PyKCS11.LowLevel.CKA_PRIVATE, PyKCS11.LowLevel.CK_TRUE)
        ]
        master = self.session.createObject(master_key_template)
        return master_key

    def __generate_user_id(self):
        user_id = uuid.uuid4()
        user_id_template = [
            (PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_DATA),
            (PyKCS11.LowLevel.CKA_VALUE, str(user_id).encode()),
            (PyKCS11.LowLevel.CKA_TOKEN, PyKCS11.LowLevel.CK_TRUE),
            (PyKCS11.LowLevel.CKA_LABEL, "User ID"),
        ]
        user_id_obj = self.session.createObject(user_id_template)
        return user_id
    
    def create_user(self):
        self.__init_crypto_context()
        master_key = self.__master_key_generate()
        user_id = self.__generate_user_id()
        salt = self.__generate_salt()
        self.__session_end()
        return [user_id, salt]

    def get_master_key_and_userID(self):
        """
        Get UserID and master key in bytes
        """
        self.__init_crypto_context()
        
        objects = self.session.findObjects([
                (PyKCS11.LowLevel.CKA_LABEL, "Master Key")
        ])

        for obj in objects:
            attr = self.session.getAttributeValue(obj, [PyKCS11.LowLevel.CKA_VALUE])
            master_key = attr[0]

        objects = self.session.findObjects([
                (PyKCS11.LowLevel.CKA_LABEL, "User ID")
        ])
        for obj in objects:
            attr = self.session.getAttributeValue(obj, [PyKCS11.LowLevel.CKA_VALUE])
            user_id = attr[0]
        self.__session_end()

        return bytes(master_key), bytes(user_id)

    def key_change(self):
        """
        Changing master key
        """
        self.__init_crypto_context()
        
        master_keys = self.session.findObjects([
                (PyKCS11.LowLevel.CKA_LABEL, "Master Key")
        ])
        self.session.destroyObject(master_keys[0])
        master_key = self.__master_key_generate()
        self.__session_end()
        return master_key
    
    def delete_user(self):
        """
        Deleting UserID and master key of all users from token
        """
        self.__init_crypto_context()
        objects = self.session.findObjects([
                (PyKCS11.LowLevel.CKA_LABEL, "Master Key")
        ])
        for obj in objects:
            self.session.destroyObject(obj)

        objects = self.session.findObjects([
                (PyKCS11.LowLevel.CKA_LABEL, "User ID")
        ])
        for obj in objects:
            self.session.destroyObject(obj)
        self.__session_end()
        return {"status": "data_deleted"}
    
    def check_token(self):
        self.__init_lib()
        try:
            self.pkcs11.getMechanismList(self.slot)
            
            return {"status": "Token is found"}
        except:
            return {"status": "Token not found"}
        
    def return_hash(self, text: bytes):
        hash = hashes.Hash(hashes.SHA256())
        hash.update(text)
        return(hash.finalize())