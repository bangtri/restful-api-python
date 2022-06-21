import sqlite3


def find_all_users():
    conn = sqlite3.connect('data/python.db')
    cursor = conn.cursor()
    data = cursor.execute('SELECT * FROM users').fetchall()
    conn.close()
    return data


def insert_user(id, email, phone, firstName, lastName):
    conn = sqlite3.connect('data/python.db')
    cursor = conn.cursor()
    query = 'INSERT INTO users (id, email, phone, firstName, lastName) VALUES (?, ?, ?, ?, ?)'
    data_tuple = (id, email, phone, firstName, lastName)
    cursor.execute(query, data_tuple)
    conn.commit()
    cursor.close()
