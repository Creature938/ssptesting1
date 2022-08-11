from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_recaptcha import ReCaptcha
from flask_bootstrap import Bootstrap
import pyotp
from password_strength import PasswordPolicy
from password_strength import PasswordStats
from flask_bcrypt import bcrypt
import MySQLdb.cursors
import bcrypt
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import mysql.connector as connection
import pandas as pd

app = Flask(__name__)
# Change this to your secret key (can be anything, it's for extra protection)
policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=1,  # need min. 2 uppercase letters
    numbers=1,  # need min. 2 digits
    strength=0.50 # need a password that scores at least 0.5 with its entropy bits
)
app.secret_key = 'your secret key'
# Enter your database connection details below
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Catus14juice2'
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['RECAPTCHA_SITE_KEY'] = '6LerU_ogAAAAAM3UWoEhSj1ups9Buupha2vEJzD3'
app.config['RECAPTCHA_SECRET_KEY'] = '6LerU_ogAAAAAPfspsQwzHXxcDYlBIhckQJw_af_'
recaptcha = ReCaptcha(app)
Bootstrap(app)
# Intialize MySQL
mysql = MySQL(app)


# http://localhost:5000/MyWebApp/ - this will be the login page, we need to use both GET and POST
#requests
@app.route('/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
    # Create variables for easy access
        username = request.form['username']
        password = request.form['password']

        #email = request.form['email']
        if request.method == 'POST': # Check to see if flask.request.method is POST
             if recaptcha.verify(): # Use verify() method to see if ReCaptcha is filled out
        # Check if account exists using MySQL
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
                mysql.connection.commit()
            # Fetch one record and return result
                account = cursor.fetchone()
                cursor.execute('select password from accounts where username = %s', (username,))
                mysql.connection.commit()
                sqlPassword = cursor.fetchone()["password"]
                passwd = password.encode('utf-8')

                if bcrypt.checkpw(passwd, (bytes(sqlPassword, 'utf-8'))):

        # Create session data, we can access this data in other routes
                #if password == sqlPassword:
                    session['loggedin'] = True
                    session['id'] = account['id']
                    session['username'] = account['username']
                else:
                    msg = 'Incorrect username/password!'
                    return render_template('index.html', msg=msg)
        # Redirect to home page
                return redirect(url_for("login_2fa", msg=msg))
             else:
                 msg = 'Please fill out the ReCaptcha!'

                 return render_template('index.html', msg=msg)
        return username
    else:
# Account doesn’t exist or username/password incorrect
        return render_template('index.html', msg='')
# Show the login form with message (if any)

    #return render_template('index.html', msg='')


@app.route('/logout')
def logout():
# Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
# Redirect to login page
    return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
# Output message if something goes wrong...
    msg = ''
# Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
# Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        stats = PasswordStats(password)
        #cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        #w =pd.read_sql_query("select *from accounts", cursor)
        #mysql.connection.commit()
        #print(w)

        checkpolicy = policy.test(password)
        if stats.strength() < 0.50:
            print(stats.strength())
            msg = "Password not strong enough. Avoid consecutive characters and easily guessed words."
        elif stats.strength() > 0.50:
            s=password
            passwd = s.encode('utf-8')
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(passwd, salt)
            passwords = hashed
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, passwords, email,))
            mysql.connection.commit()

            msg = 'You have successfully registered!'
    elif request.method == 'POST':
# Form is empty... (no POST data)
        msg = 'Please fill out the form!'
# Show registration form with message (if any)
    return render_template('register.html', msg=msg)
# http://localhost:5000/MyWebApp/profile - this will be the profile page, only accessible for loggedin users
@app.route('/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'])
        # User is not loggedin redirect to login page
    return redirect(url_for('login'))
@app.route("/login/2fa/", methods=['GET', 'POST'])
def login_2fa():
    # generating random secret key for authentication
    secret = pyotp.random_base32()
    html = """
    <html>
        <div>
          <h5>Instructions!</h5>
          <ul>
            <li>Select time-based authentication.</li>
            <li>Submit the generated key in the form.</li>
          </ul>
        </div>
        <div>
          <label for="secret">Secret Token : </label>
          <b id="secret"> {0} </b>
        </div>
         
    """.format(secret)
    if 'loggedin' in session:
        user=session['username']
        print(user)

    mydb = connection.connect(host="localhost", database = 'pythonlogin',user="root", passwd="Catus14juice2",use_pure=True)
    query = "Select * from accounts;"
    result_dataFrame = pd.read_sql(query,mydb)
    mydb.close() #close the connection
    result_dataFrame = result_dataFrame[result_dataFrame['username'] == str(user)]

    email=list(result_dataFrame.email.values)[0]
    print(email)
    mail_content = html
    sender_address = 'tinay3871@gmail.com'
    sender_pass = 'amkgcotykxfjjigy'
    receiver_address = email
    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = 'A test mail sent by Python. It has an attachment.'   #The subject line
    message.attach(MIMEText(mail_content, 'html'))
    sessions = smtplib.SMTP('smtp.gmail.com', 587) #use gmail with port
    sessions.starttls()
    sessions.login(sender_address, sender_pass)
    text = message.as_string()
    sessions.sendmail(sender_address, receiver_address, text)
    sessions.quit()


    return render_template("login_2fa.html", secret=secret)


@app.route('/profile')
def profile():
# Check if user is loggedin
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
        # User is not loggedin redirect to login page
    return redirect(url_for('login'))
if __name__== '__main__':
     app.run()
