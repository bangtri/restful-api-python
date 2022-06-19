import sqlite3


def find_all_users(query):
    conn = sqlite3.connect('data/python.db')
    data = conn.execute(query).fetchall()
    conn.close()
    return data
