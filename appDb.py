import sqlite3
from flask import Flask, render_template, request, redirect, flash, url_for
from hashlib import sha256
import os


app = Flask(__name__)
app.secret_key = os.urandom(24)

#   Creating and connecting to be DB.
DBNAME = 'DigiSign.db'
conn = sqlite3.connect(DBNAME)

print("Database creation successful.")


#   Creating a table
#def createTable():
#    conn.execute('''CREATE TABLE users
#         (Id INTEGER PRIMARY KEY     AUTOINCREMENT,
#         username       TEXT    NOT NULL,
#         password       TEXT    UNIQUE  NOT NULL);''')
#    print("Table created successfully.")


