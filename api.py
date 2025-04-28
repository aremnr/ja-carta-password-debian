from fastapi import FastAPI
from pydantic import BaseModel
from main import get_all, get_correct, add_data, delete_data, delete_db, clear_db, change_data, check_token, create_db, key_change, get_fuzzy

app = FastAPI()

class Data(BaseModel):
    login: str = ""
    password: str = ""
    domain: str = ""

class Id(BaseModel):
    id: int

class DataList(BaseModel):
    data_list: list[Data]

@app.get('/get_all')
def get():
    data = get_all()
    # ret_data = DataList(data_list=[])
    # for i in range(0, len(data), 3):
    #     new = Data(domain=data[i], login=data[i+1], password=data[i+2])
    #     ret_data.data_list.append(new)
    #     del new
    return {"password_count": data}

@app.get("/create_db")
def create():
    return create_db()

@app.post("/add_data")
def add(data: Data):
    if get_correct(data.domain) == {}:
        return add_data(data.domain, data.login, data.password)
    return {"status": "domain_is_already_in_db"}

@app.post("/get_correct")
def correct(data: Id):
    data = get_correct(id=data.id)
    if type(data) != dict:
        r_data = Data(login=data[1], password=data[2], domain=data[0])
        return r_data
    return data

@app.get("/check_token")
def check():
    return check_token()

@app.put("/change_key")
def change_k():
    return key_change()

@app.post("/delete_data")
def delete_d(data: Data):
    return delete_data(data.domain)

@app.delete("/delete_db")
def delete_database():
    return delete_db()

@app.put("/clear_db")
def clear():
    return clear_db()

@app.post("/change_data")
def change(data: Data):
    return change_data(data.domain, data.login, data.password)

@app.post("/get_fuzzy")
def fuzzy(data: Data):
    data = get_fuzzy(data.domain)
    ret_data = DataList(data_list=[])
    for i in range(0, len(data), 3):
        new = Data(domain=data[i], login=data[i+1], password=data[i+2])
        ret_data.data_list.append(new)
        del new
    return ret_data