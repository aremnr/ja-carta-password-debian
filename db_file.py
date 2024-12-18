import os
import os.path
from typing import Any

class DB_FILE:
    def __init__(self, name: str):
        self.filename = name
    
    def create_db_dir(self):
        if not(os.path.exists(f"./db_files/")):
            os.mkdir("./db_files/")
        
    def check_db_file(self) -> bool:
        return os.path.exists(f"./db_files/{self.filename}") and os.path.isfile(f"./db_files/{self.filename}")
    
    def write_db_data(self, salt: bytes, data: Any):
        self.create_db_dir()
        with open(f"./db_files/{self.filename}", "wb") as f:
            f.write(salt)
            f.write(bytes(data))
        return True
        
    def read_db_file(self):
        if self.check_db_file():
            with open(f"./db_files/{self.filename}", "rb") as f:
                data = f.read()
                return data[:24], data[24:]
        raise Exception("File not found")