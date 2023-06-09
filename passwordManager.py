import bcrypt
import pyodbc
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, url_for, redirect


def Connection():
    server = '' 
    database = 'passwordManager'
    connection = 'DRIVER={SQL Server};SERVER=' + server + ';DATABASE=' + database + ';Trusted_Connection=yes;'
    return connection

# name of the module
manager = Flask(__name__)

@manager.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        userGet = request.form.get("userName")
        passwordGet = request.form.get("password")

        userName = str(userGet)
        Password = str(passwordGet)
        encodePassword = Password.encode('utf-8')
        # DB CONNECTION
        connection = pyodbc.connect(Connection()) 


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
        
                return redirect(url_for("profile", user = userName))

        
    return render_template("home.html")

@manager.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        userName = request.form.get("userName")
        password = request.form.get("password")

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
        connection = pyodbc.connect(Connection())
        #calling cursor to handle queries
        cursor = connection.cursor()

        #username, salt and password inserted in the table
        cursor.execute('INSERT INTO passwordManager.dbo.users ([user], [salt], [password]) VALUES (?, ?, ?)',  (userName, saltString, passwordString))
        # the query is commited to the database and the connection and cursor are closed
        connection.commit()
        cursor.close() 
        connection.close()
        return redirect(url_for("profile", user = userName))
    return render_template("register.html")

@manager.route("/profile/<user>", methods=["GET", "POST"])
def profile(user):
    return render_template("profile.html", name = user)

@manager.route("/Modify/<user>/<service>/<password>", methods=["GET", "POST"])
def Modify(user, service, password):
    return render_template("Modify.html", name = user, x = service, y = password)

@manager.route("/ModifyPassword/<user>/<service>/<password>", methods=["GET", "POST"])
def ModifyService(user, service, password):
    if request.method == "POST":
        getNewPassword = request.form.get("password2")
        userName = user
        passwordService = service

        #encrypt passwords and save to db
        #1. ask for password to add
        addPassword = str(getNewPassword)
        #2. encrypt
        encodedPassword = addPassword.encode('utf-8')
        # fernet library generates encryption key
        Key = Fernet.generate_key()
        # fernet library is initialized with the generated key
        fernet = Fernet(Key)
        # password is encrypted
        encryptedPassword = fernet.encrypt(encodedPassword)

        # DB CONNECTION
        connection = pyodbc.connect(Connection())
        #calling cursor to handle queries
        cursor = connection.cursor()

        cursor.execute('UPDATE passwordManager.dbo.passwords SET [password] = ? WHERE [user] = ? AND [service] = ?',  (encryptedPassword.decode('utf-8'), userName, passwordService))
        cursor.execute('UPDATE passwordManager.dbo.keys SET [crypt_key] = ? WHERE [user] = ? AND [service] = ?',  (Key.decode('utf-8')), userName, passwordService)

        # the query is commited to the database and the connection and cursor are closed
        connection.commit()
        cursor.close() 
        connection.close()

    return render_template("Modify.html", name = user, x = service, y = password)

@manager.route("/ModifyService/<user>/<service>/<password>", methods=["GET", "POST"])
def ModifyPassword(user, service, password):
    if request.method == "POST":
        getNewService = request.form.get("service")
        userName = user
        passwordService = service
        # DB CONNECTION
        connection = pyodbc.connect(Connection())
        #calling cursor to handle queries
        cursor = connection.cursor()
        cursor.execute('UPDATE passwordManager.dbo.passwords SET [service] = ? WHERE [user] = ? AND [service] = ?',  (getNewService, userName, passwordService))
        cursor.execute('UPDATE passwordManager.dbo.keys SET [service] = ? WHERE [user] = ? AND [service] = ?',  (getNewService, userName, passwordService))
        # the query is commited to the database and the connection and cursor are closed
        connection.commit()
        cursor.close() 
        connection.close()

    return render_template("Modify.html", name = user, x = service, y = password)

@manager.route("/Add/<user>", methods=["GET", "POST"])
def test(user):
    return render_template("Add.html", name = user)

@manager.route("/delete/<user>/<service>", methods=["GET", "POST"])
def delete(user, service):
    if request.method == "POST":
        userName = user
        passwordService = service
        connection = pyodbc.connect(Connection()) 
        cursor = connection.cursor() 
        #DELETE FROM [dbo].[passwords]WHERE [user] = 'josh' AND [service] = 'netflix';
        cursor.execute('DELETE FROM passwordManager.dbo.passwords WHERE [user] = ? AND [service] = ?',  (userName, passwordService))
        cursor.execute('DELETE FROM passwordManager.dbo.keys WHERE [user] = ? AND [service] = ?',  (userName, passwordService))
        # the query is commited to the database and the connection and cursor are closed
        connection.commit()
        cursor.close() 
        connection.close()
        # TO DO return redirect(url_for("ViewPassword", name = user)) look at AddPassword section
    return render_template("delete.html", x = service, name = user)

@manager.route("/AddPassword/<user>", methods=["GET", "POST"])
def AddPassword(user):
    if request.method == "POST":
        getPassword = request.form.get("password")
        getService = request.form.get("service")

        #if getPassword == 'None' or getService == 'None':
            #return render_template("AddPassword.html", name = user)

        userName = user
        #encrypt passwords and save to db
        #1. ask for password to add
        addPassword = str(getPassword)
        addService = str(getService)
        #2. encrypt
        encodedPassword = addPassword.encode('utf-8')
        # fernet library generates encryption key
        Key = Fernet.generate_key()
        # fernet library is initialized with the generated key
        fernet = Fernet(Key)
        # password is encrypted
        encryptedPassword = fernet.encrypt(encodedPassword)

        # DB CONNECTION
        connection = pyodbc.connect(Connection())
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
        #return redirect(url_for("profile", user = userName))
        return redirect(url_for("profile", user = userName))
    #return render_template("AddPassword.html", name = user)
    
@manager.route("/ViewPassword/<user>", methods=["GET", "POST"])
def ViewPassword(user):
    userName = user

    #retrieve encrypted passwords from database and display
    #1. get encrypted passwords for the user above from the password table
    # DB CONNECTION
    connection = pyodbc.connect(Connection())
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

    printPasswords = {}

    #2. decrypt them
    for i in passwordDict:
        for x in keyDict:
            if i == x:
                fernet = Fernet(keyDict[x].encode('utf-8'))
                decryptedPass = fernet.decrypt(passwordDict[i].encode('utf-8')).decode('utf-8')
                printPasswords[x] = decryptedPass

    return render_template("ViewPassword.html", len = len(printPasswords), printPasswords = printPasswords, name = user)

# this runs the application
#if __name__ == "__main__":
    #manager.run(debug=True)
