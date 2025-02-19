#  Минимальная документация

## Аргументы:
| flag | Значение |
|:----:|:--------:|
| -d   | Доменное имя |
| -p   | Пароль |
| -u   | Имя пользователя |
| -m   | Метод(режим) работы |


## Примеры использования
Создание базы данных и пользователя (одно без другого не происходит)
```bash
python3 main.py -m "create database"
```

Добавление данных
```bash
python3 main.py -m "add data" -d example.com -u admin -p admin
```

Получение всех данных
```bash
python3 main.py -m "get all"
```

Получение конкретных данных про один домен
```bash
python3 main.py -m "get correct" -d example.com
```

Изменение ключа безопасности
```bash
python3 main.py -m "key change"
```
