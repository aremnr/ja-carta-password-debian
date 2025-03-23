from fastapi import FastAPI
from pydantic import BaseModel
from main import get_all, get_correct, add_data, delete_data, delete_db, clear_db, change_data, check_token, create_db, key_change

app = FastAPI()

class Data(BaseModel):
    login: str = ""
    password: str = ""
    domain: str = ""

class DataList(BaseModel):
    data_list: list[Data]

@app.get('/get_all')
def get():
    _, data, _ = get_all()
    data = list(data.replace("\x00", "").split())
    ret_data = DataList(data_list=[])
    for i in range(0, len(data), 3):
        new = Data(domain=data[i], login=data[i+1], password=data[i+2])
        ret_data.data_list.append(new)
        del new
    return ret_data

@app.get("/create_db")
def create():
    return create_db()

@app.post("/add_data")
def add(data: Data):
    return add_data(data.domain, data.login, data.password)

@app.get("/get_correct")
def create(domain: str):
    return get_correct(domain)

@app.get("/check_token")
def check():
    return check_token()

@app.put("/change_key")
def change_k():
    return key_change()

@app.delete("/delete_data")
def delete_d(domain: str):
    return delete_data(domain)

@app.delete("/delete_db")
def delete_database():
    return delete_db()

@app.put("/clear_db")
def clear():
    return clear_db()

@app.post("/change_data")
def change(data: Data):
    return change_data(data.domain, data.login, data.password)