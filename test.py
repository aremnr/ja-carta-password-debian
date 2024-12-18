from PyKCS11 import PyKCS11
from PyKCS11.LowLevel import *
import os
# Initialize PKCS#11 module
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load("/usr/lib/libjcPKCS11-2.so")
# Open a session with the token (you might need to adjust the slot and PIN)
slot = pkcs11.getSlotList(tokenPresent=True)[0]  # assuming the first slot
session = pkcs11.openSession(slot)
session.login("1234567890")
# Define the secret key attributes

class_id = CKO_SECRET_KEY
key_type = CKK_GOST28147
label = "A GOST 28147-89 secret key object"
value = os.urandom(32)  # 32-byte value for the secret key
params_oid = b'\x06\x07\x2a\x85\x03\x02\x02\x1f\x00'
true = CK_TRUE

# Define the attribute template
attributes = [
    (CKA_CLASS, class_id),
    (CKA_KEY_TYPE, key_type),
    (CKA_LABEL, label),
    (CKA_ENCRYPT, true),
    (CKA_GOST28147_PARAMS, params_oid),
    (CKA_VALUE, value)
]

# Create the object
secret_key = session.createObject(attributes)
session.destroyObject(attributes)
# Close the session
session.logout()
session.closeSession()
