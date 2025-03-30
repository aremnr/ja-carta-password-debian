import os
import os.path
from typing import Any

class DB_FILE:
    def __init__(self, name: str):
        self.filename = name
    
    def create_db_dir(self):
        if not(os.path.exists("./db_files/")):
            os.mkdir("./db_files/")
        
    def check_db_file(self) -> bool:
        return os.path.exists(f"./db_files/{self.filename}") and os.path.isfile(f"./db_files/{self.filename}")
    
    def init_db(self):
        self.create_db_dir()
        with open(f"./db_files/{self.filename}", "wb") as f:
            f.write(b"\n")
        return True

    def write_db_data(self, domains, passwds):
        if self.check_db_file():
            with open(f"./db_files/{self.filename}", "wb") as f:
                f_dom = ";".join(domains)
                f_passwds = "".join(i.decode() for i in passwds)
                new_data = f"{f_dom}\n{f_passwds}"
                f.write(new_data.encode())
 
    def read_db_file(self):
        if self.check_db_file():
            with open(f"./db_files/{self.filename}", "rb") as f:
                domains = f.readline().decode()
                if domains.strip("\n"):
                    domains = domains.strip("\n").split(";")
                    passwds = f.readlines() 
                else:
                    domains = []
                    passwds = []
                return domains, passwds
        raise Exception("File not found")
    
    def clear_db(self):
        self.write_db_data(b"", b"")
        return {"status": "db_clear"}
    
    def delete_db(self):
        if self.check_db_file():
            os.remove(f"./db_files/{self.filename}")
            return {"status" : "db_deleted"}