import bcrypt
import pyodbc
import sys
from cryptography.fernet import Fernet
import time


def menu():
    time.sleep(1)
    print("1. Add password:  ")
    print("2. See passwords:  ")
    print("Q. Exit:  ")

def Add():
    #encrypt passwords and save to db
    #1. ask for password to add
    addPassword = input("\nPassword >>  ")
    addService = input("\nService >>  ")
    #2. encrypt
    encodedPassword = addPassword.encode('utf-8')
    # fernet library generates encryption key
    Key = Fernet.generate_key()
    # fernet library is initialized with the generated key
    fernet = Fernet(Key)
    # password is encrypted
    encryptedPassword = fernet.encrypt(encodedPassword)

    # DB CONNECTION
    server = '' 
    database = 'passwordManager'
    #db connection
    connection = pyodbc.connect('DRIVER={SQL Server};SERVER=' + server + ';DATABASE=' + database + ';Trusted_Connection=yes;') 
    #calling cursor to handle queries
    cursor = connection.cursor()

    #3. save to database with the user name from above
    #username, password encrypted and service added to table
    cursor.execute('INSERT INTO passwordManager.dbo.passwords ([user], [password], [service]) VALUES (?, ?, ?)',  (userName, encryptedPassword.decode('utf-8') , addService))
    # the query is commited to the database and the connection and cursor are closed
    cursor.execute('INSERT INTO passwordManager.dbo.keys ([user], [service], [crypt_key]) VALUES (?, ?, ?)',  (userName, addService, Key.decode('utf-8')))
    # the query is commited to the database and the connection and cursor are closed
    connection.commit()
    cursor.close() 
    connection.close()
    #4 go back to menu


def display():
    #retrieve encrypted passwords from database and display
    #1. get encrypted passwords for the user above from the password table
    # DB CONNECTION
    server = '' 
    database = 'passwordManager'
    connection = pyodbc.connect('DRIVER={SQL Server};SERVER=' + server + ';DATABASE=' + database + ';Trusted_Connection=yes;') 
    cursor = connection.cursor() 

    cursor.execute('SELECT password, service FROM passwordManager.dbo.passwords WHERE [user] = ?', userName)

    # fetch the results 
    results = cursor.fetchall() 
    passwordDict = {}

    for row in results:
        # get the salt from results
        dbPassword = row[0]
        #encodePassword = dbPassword.encode('utf-8')
        # get the password from the que
        dbService = row[1]
        passwordDict[dbService] = dbPassword


    cursor.execute('SELECT service, crypt_key FROM passwordManager.dbo.keys WHERE [user] = ?', userName)

    # fetch the results 
    results = cursor.fetchall()
    keyDict = {}

    for row in results:
        # get the salt from results
        dbServiceKey = row[0]
        #encodePassword = dbPassword.encode('utf-8')
        # get the password from the query
        dbKey = row[1]
        keyDict[dbServiceKey] = dbKey

    cursor.close() 
    connection.close()

    print("+---------------------------------+")
    print("|            Passwords            |")
    print("+---------------------------------+")
    print("| Service   | Password            |")
    print("+---------------------------------+")
    #2. decrypt them
    for i in passwordDict:
        for x in keyDict:
            if i == x:
                fernet = Fernet(keyDict[x].encode('utf-8'))
                decryptedPass = fernet.decrypt(passwordDict[i].encode('utf-8')).decode('utf-8')
                print("\n", "|", x, "| ", decryptedPass)
                print("+---------------------------------+")






#username and password input is collceted. username will be used to get the hashed password and salt from the database and password will be used to compare 
#the original one

account = 1

# while loop to check if correct input added. if any of Q, q, 1 or 2 added it will either exit or proceed. and is used because it can not be aby of those inputs
# for the loop to keep going. or would mean that it can not be one of those inputs bu the rest is fine.
while not account == "Q" and not account == "q" and not account == "1" and not account == "2":
    print("\n1. Create account\n2. Log In\nQ. Exit")
    account = input("\n>>> ")
    print("\n")

if account == "1":

    userName = input("\nUser Name >>   ")
    password = input("\nPassword >>   ")

    # password to compare is encoded cause need to be
    Password = password.encode('utf-8')

    # password salt is saved to a variable
    salt = bcrypt.gensalt(10)

    #the original password is hashed and salted
    hashPassword = bcrypt.hashpw(Password, salt)

    #the final password hash is decoded as well as the salt so they can be saved in the database
    passwordString = hashPassword.decode('utf-8')
    saltString = salt.decode('utf-8')

    # DB CONNECTION
    server = '' 
    database = 'passwordManager'
    #db connection
    connection = pyodbc.connect('DRIVER={SQL Server};SERVER=' + server + ';DATABASE=' + database + ';Trusted_Connection=yes;') 
    #calling cursor to handle queries
    cursor = connection.cursor()

    #username, salt and password inserted in the table
    cursor.execute('INSERT INTO passwordManager.dbo.users ([user], [salt], [password]) VALUES (?, ?, ?)',  (userName, saltString, passwordString))
    # the query is commited to the database and the connection and cursor are closed
    connection.commit()
    cursor.close() 
    connection.close()

    print("\n>>> Welcome ", userName, " <<<\n")
    choice = 1
    while not choice == "Q" and not choice == "q":
        menu()
        choice = input("\n>>> ")

        if choice == "1":
            Add()
            choice = 2

        elif choice == "2":
            display()



if account == "2":

    userName = str(input("User name:  "))
    Password = str(input("Password:  "))
    encodePassword = Password.encode('utf-8')
    # DB CONNECTION
    server = '' 
    database = 'passwordManager'
    connection = pyodbc.connect('DRIVER={SQL Server};SERVER=' + server + ';DATABASE=' + database + ';Trusted_Connection=yes;') 


    cursor = connection.cursor() 

    cursor.execute('SELECT salt, password FROM passwordManager.dbo.users WHERE [user] = ?', userName)


    # fetch the results 
    results = cursor.fetchall() 

    # print the results 
    for row in results:
        # get the salt from results
        dbSalt = row[0]
        # get the password from the query
        dbPassword = row[1]
        # encode salt from the db cause before we saved we decoded it. this might not be necceseray will check next time ///TODO///
        encodeSalt = dbSalt.encode('utf-8')
        # encode password from the db cause before saving it was decoded
        encodeDBPassword = dbPassword.encode('utf-8')

        # compare the encode hashed password from database to encoded password that user provides
        if bcrypt.checkpw(encodePassword, encodeDBPassword):
            print("\n>>> Welcome ", userName, " <<<\n")
            choice = 1
            while not choice == "Q" and not choice == "q":
                menu()
                choice = input("\n>>> ")

                if choice == "1":
                    Add()
                    choice = 2

                elif choice == "2":
                    display()
    else:
        cursor.close() 
        connection.close()
        print("\nIncorrect password")

else:
    cursor.close() 
    connection.close()
    print("\nIncorrect password")