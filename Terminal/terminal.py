import sqlite3
import getpass
from hashlib import pbkdf2_hmac
import os
from Crypto.Cipher import AES

con = sqlite3.connect("tutorial.db")
cur = con.cursor()

def main():
    mode=int(input("Login [0] or Create User [1]: "))
    if mode:
        username = str(input("Enter a username: "))
        password = getpass.getpass(prompt="Enter a password: ")
        createUser(username, password)
    username = str(input("Enter a username: "))
    password = getpass.getpass(prompt="Enter a password: ")
    if authenticate(username, password):
        printSecret()
    else:
        exit()
    while 1:
        mode=int(input("Exit [0] or Edit Secret [1]: "))
        if mode:
            editSecret()
        else:
            exit()
            
def createUser(user, password):
    cur.execute("SELECT * FROM user WHERE name=?",(user,))
    if cur.fetchall():
        return False
    salt=bytes(os.urandom(16).hex(), 'utf-8')
    password = pbkdf2_hmac('sha256', str.encode(password), salt, 1000)
    data=[(user,password,salt,'')]
    cur.execute("INSERT INTO user VALUES(?,?,?,?)",data)
    con.commit()

def editSecret():
    print("hello")

def printSecret():
    print("hello")

def authenticate(userlogin, passwordlogin):
    cur.execute("SELECT hash, salt FROM user WHERE name=?",(userlogin,))
    row=cur.fetchall()
    for i in row:
        salthash=i
    password = pbkdf2_hmac('sha256', str.encode(passwordlogin), salthash[1], 1000)
    if password==salthash[0]:
        print("Uwu you did it!")
        return 1
    else:
        print("Owo something went wrong :(")
        return 0

if __name__ == '__main__':
    main()