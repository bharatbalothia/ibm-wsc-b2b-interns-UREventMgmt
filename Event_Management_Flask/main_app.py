from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, send_file
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField,  RadioField, IntegerField, BooleanField
from wtforms.fields.html5 import DateField
import couchdb
from ldap3 import *
from passlib.hash import sha256_crypt
from functools import wraps
from fpdf import FPDF
import csv
import datetime
import pandas as pd
from datetime import date
app = Flask(__name__)
 
SECRET_KEY = '\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"\xa1\xa8'
app.secret_key=SECRET_KEY


Date = date.today()
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=5)

# Index
@app.route('/')
def index():
    if 'logged_in' in session and session['logged_in'] == True:
        return render_template('user.html')
    return redirect(url_for('login'))
#Couch Authorization
def authorizeCouch():
    user = "admin"
    password = "admin"
    return couchdb.Server("http://%s:%s@9.199.145.49:5984/" % (user, password))


#db Creation/Selection in couch
def dbCreate(dbname,couchserver):
    if dbname in couchserver:
        db = couchserver[dbname]
    else:
        db = couchserver.create(dbname)
    return db


couchserver = authorizeCouch()

#Call all the databases need
db = dbCreate("events",couchserver)
db_users = dbCreate("events_users",couchserver)
db_auth = dbCreate("events_auth_info",couchserver)



#Verify Admin/User - Is called at the end of LDAP authentication
def auth_user(id):
    for i in db_auth:
        if id in db_auth[i]['admins']:
            session['isAdmin']=True
            session['isUser']=False
            return 'admin'
        elif id in db_auth[i]['users']:
            session['isAdmin']=False
            session['isUser']=True
            return 'user'
        
       

#Upcoming Events
def upcoming_events():
    upcoming_events=[]
    
    for i in db:
        content={}
        Event_Date= datetime.datetime.strptime(db[i]['startdate'],"%d-%m-%Y").date()
        if  Event_Date >= Date :
            content['event_name']= ""+db[i]['event_name']
            content['college_name']=""+db[i]['college_name']
            content['startdate']=""+db[i]['startdate']
        if len(content)!=0:
            upcoming_events.append(content)
        
    
    session['UpcomingEvents']=upcoming_events
    return upcoming_events



        
# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        POST_USERNAME = str(request.form['uname'])
        POST_PASSWORD = str(request.form['pass'])

        for i in db:
            if db[i]['type'] == 'user':
                if db[i]['username'] == POST_USERNAME:
                    session['logged_in'] = True
                    session['username'] = POST_USERNAME

                    # flash('You are now logged in', 'success')
                    return redirect(url_for('index'))


        server = Server('ldap://bluepages.ibm.com', get_info=ALL)
        c = Connection(server, user="", password="", raise_exceptions=False)
        noUseBool = c.bind()

        checkUserIBM = c.search(search_base='ou=bluepages,o=ibm.com',
                                search_filter='(mail=%s)' % (POST_USERNAME),
                                search_scope=SUBTREE,
                                attributes=['dn', 'givenName'])

        if (checkUserIBM == False):
            session['authorized'] = 0
            error = 'Invalid login'
            return render_template('login.html', error=error)

        # get the username of the emailID and authenticate password
        userName = c.entries[0].givenName[0]
        uniqueID = c.response[0]['dn']
        c2 = Connection(server, uniqueID, POST_PASSWORD)
        isPassword = c2.bind()

        if (isPassword == False):
            session['authorized'] = 0
            error = 'Invalid login'
            return render_template('login.html', error=error)

        # now search group
        checkIfAdminGroup = c.search(search_base='cn=RSC_B2B,ou=memberlist,ou=ibmgroups,o=ibm.com',
                                     search_filter='(uniquemember=%s)' % (str(uniqueID)),
                                     search_scope=SUBTREE,
                                     attributes=['dn'])

        if (checkIfAdminGroup == False):
            session['authorized'] = 0
            error = 'Invalid login'
            return render_template('login.html', error=error)

        # control reaches here if user password and group authentication is successful

        session['logged_in'] = True
        session['username'] = userName
        session['usermail']= POST_USERNAME

        #flash('You are now logged in', 'success')
        
        if auth_user(POST_USERNAME)=='admin':
            print('ADMIN')
            return  render_template('user.html',Events=upcoming_events())
        elif auth_user(POST_USERNAME)=='user':
            print('USER')
            return  render_template('user.html',Events=upcoming_events())


    return render_template('login.html')



#Other Utility Functions
def getEventDetails(name):
    content={}
    print('Fetching Event Details')
    
    




@app.route('/applied_events', methods=['GET','POST'])
def applied_events():
    content={}
    print('Applied Events Function Route')
    for i in db_users:
        if db_users[i]['user_mail'] == session['usermail']:
            for j in db_users[i]['applied_events']:
                print(j.value)

    return render_template('applied_events.html')

@app.route('/complted_events', methods=['GET','POST'])
def completed_events():
   
    return render_template('completed_events.html')
 
@app.route('/event_details')
def event_details():
    return render_template('event_details.html')


@app.route('/user')
def user():
    return render_template('user.html')

@app.route('/manage_events')
def create_events():
    return render_template('create_events.html')

@app.route('/manage_users')
def manage_users():
    return render_template('manage_users.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login')) 

    return wrap



# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    session['logged_in'] = False
    flash('You have logged out', 'success')
    return redirect(url_for('login'))
    


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int("85"),debug=True)