#terminal.py by tatiana.
#this code is interacting with a secrets database using a command line interface.

#library imports
import sqlite3
import getpass
from hashlib import pbkdf2_hmac
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#global variables
connection = sqlite3.connect("terminal.db")
cursor = connection.cursor()
session={"username": "", "IV": b'', "key": b''}

def main():
    mode=int(input("Login [0] or Create User [1]: "))
    if mode:
        while 1:
            print("Create User")
            username = str(input("Enter a username: "))
            password = getpass.getpass(prompt="Enter a password: ")
            if createUser(username, password):
                break
    while 1:
        print("Login")
        username = str(input("Enter a username: "))
        password = getpass.getpass(prompt="Enter a password: ")
        if authenticate(username, password):
            printSecrets()
            break
    while 1:
        mode=int(input("Exit [0] or add Secret [1]: "))
        if mode:
            secret = str(input("Enter a secret: "))
            addSecret(str.encode(secret))
            printSecrets()
        else:
            exit()
            
def createUser(username, password):
    cursor.execute("SELECT * FROM users WHERE username=?",(username,))
    if cursor.fetchall():
        return 0
    salt=os.urandom(16)
    hash = pbkdf2_hmac('sha256', str.encode(password), salt, 1000)
    initializationVector=os.urandom(16)
    userData=(username, salt, hash, initializationVector)
    cursor.execute("INSERT INTO users VALUES(?,?,?,?)",userData)
    connection.commit()
    return 1

def addSecret(secret):
    cipher= AES.new(session["key"], AES.MODE_CBC, session["IV"])
    secret=cipher.encrypt(pad(secret, AES.block_size))
    cursor.execute("SELECT * FROM secrets WHERE username=?",(session["username"],))
    rows=cursor.fetchall()
    secretIndex=0
    for i in rows:
        secretIndex+=1
    secretData=(session["username"], session["IV"], secretIndex, secret)
    cursor.execute("INSERT INTO secrets VALUES(?,?,?,?)",secretData) 
    connection.commit()

def deleteSecret():
    return 0

def editSecret():
    return 0

def printSecrets():
    cursor.execute("SELECT secretIndex, secret FROM secrets WHERE username=?",(session["username"],))
    rows=cursor.fetchall()
    if rows:
        pass
    else:
        print("profile has no secrets")
        return 0
    secrets=[i for i in rows]
    format="{}: {}"
    for i in secrets:
        cipher = AES.new(session["key"], AES.MODE_CBC, session["IV"])
        print(format.format(i[0],unpad(cipher.decrypt(i[1]), AES.block_size).decode('utf-8')))

def authenticate(username, password):
    cursor.execute("SELECT * FROM users WHERE username=?",(username,))
    row=cursor.fetchall()
    for i in row:
        userData=i
    hash = pbkdf2_hmac('sha256', str.encode(password), userData[1], 1000)
    if hash==userData[2]:
        print("Uwu you did it!")
        key = pbkdf2_hmac('sha256', str.encode(password), userData[3], 1000)
        session.update({"username": username, "IV": userData[3], "key": key})
        return 1
    else:
        print("Owo something went wrong :(")
        return 0

if __name__ == '__main__':
    main()