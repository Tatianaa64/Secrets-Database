#init.py by tatiana.
#this code is generating the template database, example user, and secrets.

#library imports
import sqlite3
from hashlib import pbkdf2_hmac
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#global variables
connection = sqlite3.connect("init.db")
cursor = connection.cursor()

def main():
    #generateTemplate()
    #generateExampleUser()
    exampleLogIn("bryson", b'welcometothemaidcafe')

def generateTemplate():
    cursor.execute("CREATE TABLE users(username, salt, hash, initializationVector)")
    cursor.execute("CREATE TABLE secrets(username, initializationVector, secretIndex, secret)")

def addSecret(username, key, secret, initializationVector):
    cipher= AES.new(key, AES.MODE_CBC, initializationVector)
    secret=cipher.encrypt(pad(secret, AES.block_size))
    cursor.execute("SELECT * FROM secrets WHERE username=?",(username,))
    rows=cursor.fetchall()
    secretIndex=0
    for i in rows:
        secretIndex+=1
    secretData=(username, initializationVector, secretIndex, secret)
    cursor.execute("INSERT INTO secrets VALUES(?,?,?,?)",secretData) 
    connection.commit()

def generateExampleUser():
    username="bryson"
    password=b'welcometothemaidcafe'
    salt=os.urandom(16)
    hash=pbkdf2_hmac('sha256', password, salt, 1000)
    initializationVector=os.urandom(16)
    key=pbkdf2_hmac('sha256', password, initializationVector, 1000)
    userData=(username, salt, hash, initializationVector)
    cursor.execute("INSERT INTO users VALUES(?,?,?,?)",userData)
    connection.commit()
    addSecret(username, key, b'we are cuter than kittens', initializationVector)
    addSecret(username, key, b'are you here for the gamer discount?', initializationVector)

def exampleLogIn(username, password):
    wrongPassword=b'123456'
    cursor.execute("SELECT * FROM users WHERE username=?",(username,))
    rows=cursor.fetchall()
    for i in rows:
        loginData=i
    loginAttmepts=[pbkdf2_hmac('sha256', wrongPassword, loginData[1], 1000), pbkdf2_hmac('sha256', password, loginData[1], 1000)]
    for i in loginAttmepts:
        if i==loginData[2]:
            print("UwU you did it!")
        else:
            print("OwO something went wrong :(")
    key=pbkdf2_hmac('sha256', password, loginData[3], 1000)
    cursor.execute("SELECT secretIndex, secret FROM secrets WHERE username=?",(username,))
    rows=cursor.fetchall()
    secrets=[i for i in rows]
    format="{}: {}"
    for i in secrets:
        cipher = AES.new(key, AES.MODE_CBC, loginData[3])
        print(format.format(i[0],unpad(cipher.decrypt(i[1]), AES.block_size).decode('utf-8')))

if __name__ == '__main__':
    main()
