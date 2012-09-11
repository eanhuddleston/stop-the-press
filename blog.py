#!/usr/bin/env python
#
# A blog project meant to demonstrate various basic web development
# techniques.
# Author: Ean Huddleston (ean.huddleston@gmail.com)
# Date: 9/12
#
# This is a web app written for Google's App Engine. It includes
# several "handlers" used to process webpage requests.
#

import os
import webapp2
import re
import jinja2
from google.appengine.ext import db
import hashlib
import hmac
import random
import string
import json
from time import time
from google.appengine.api import memcache
import logging

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
        loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

SECRET = "thisissosecret"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

#############################
### Blog-specific code start
#############################

class Entry(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def top_entries(update=False):
    key = 'top'
    tup = memcache.get(key)
    ts2 = time()    # time when memcache was accessed
    if tup is None or update:   # nothing in cache, or update requested
        logging.error("DB QUERY")
        entries = db.GqlQuery("select * from Entry order by created desc")
        entries = list(entries[0:5])
        ts1 = time()
        tup = (ts1, entries)
        memcache.set(key, tup)
        deltaTime = "0"
    else:   # no db request needed, so just use entries from memcache
        ts1 = tup[0]
        entries = tup[1]
        deltaTime = str(int(ts2 - ts1))
    return entries, deltaTime
    
def get_entry(entry_id):
    entry_id = str(entry_id)
    tup = memcache.get(entry_id)    # use entry_id as key
    ts2 = time()    # time when memcache was accessed
    if tup is None:     # nothing in cache
        logging.error("DB QUERY")
        entries = Entry.get_by_id(int(entry_id))
        if entries:     # an entry with this id exists in db
            ts1 = time()
            tup = (ts1, entries)
            memcache.set(entry_id, tup)
            deltaTime = "0"
        else:   # this entry is not in db
            entries = None
            deltaTime = "0"
    else:   # no db request needed
        ts1 = tup[0]
        entries = tup[1]
        deltaTime = str(int(ts2 - ts1))
    return entries, deltaTime

class Blog(Handler):
    def get(self):
        # check if user logged in
        user = login_check(self)
        if user:
            userName = user
            action = "logout"
            signup = ""
        else:
            userName = "Not logged in"
            action = "login"
            signup = "signup"
            
        entries, deltaTime = top_entries()
        if deltaTime == 0:
            cacheMessage = "Page was not in cache"
        else:
            cacheMessage = "Page cached %s seconds ago" % deltaTime
        
        self.render("blogEntries.html", user=userName, action=action,
                signup=signup, entries=entries, cacheMessage=cacheMessage)
        
def login_check(self):
    # determine whether user is logged in:
    # attempt to collect user information from cookie
    # see whether info in their cookie is valid
    cookie = self.request.cookies.get('userID')
    if cookie:
        #check whether cookie info is correct
        user_id = cookie.split('|')[0]  # pull id out of cookie
        h = cookie.split('|')[1]    # pull hash out of cookie
        h2 = hash_str(user_id)
        if h == h2:     # it's a legit hash for this user_id
            user = User.get_by_id(int(user_id))     # grab user from db
            return user.username

class Permalink(Blog):
    def get(self, entry_id):
        # check if user logged in
        user = login_check(self)
        if user:
            userName = user
            action = "logout"
            signup = ""
        else:
            userName = "Not logged in"
            action = "login"
            signup = "signup"
        
        anEntry, deltaTime = get_entry(entry_id)
        
        if deltaTime == 0:
            cacheMessage = "Page was not in cache"
        else:
            cacheMessage = "Page cached %s seconds ago" % deltaTime
        
        deleteLink = "deletePost/%s" % entry_id
        
        if anEntry:     # this entry exists in db
            self.render("blogEntries.html", entries=[anEntry], user=userName, 
                action=action, signup=signup, cacheMessage=cacheMessage, 
                deleteLink=deleteLink, deleteText="delete")
        else:
            self.redirect("/")
            
class DeletePost(Handler):
    def get(self, entry_id):
        user = login_check(self)    # see if user logged in
        if user:
            anEntry = Entry.get_by_id(int(entry_id))
            if anEntry:
                anEntry.delete()
                top_entries(update=True)  # update front page entries in cache
        self.redirect("/")    
        
class BlogJSON(Handler):
    """Output all blog entries in database in JSON format."""
    
    def render_entries(self):
        entries = db.GqlQuery("select * from Entry order by created desc")
        self.render("blogEntries.html", entries=entries)
    def get(self):
        entries = db.GqlQuery("select * from Entry order by created desc")
        l = []
        for e in entries:
            d = e.created.strftime('%m-%d-%Y')
            l.append({"subject": e.subject, "content": e.content,
                "created": d})
        j = json.dumps(l)
        self.response.headers['Content-Type'] = "application/json"
        self.response.out.write(j)
            
class PermalinkJSON(Blog):
    def get(self, entry_id):
        s = Entry.get_by_id( int(entry_id) )
        if s:
            # build json object
            d = s.created.strftime('%m-%d-%Y')
            j = json.dumps([{"subject": s.subject, "content": s.content,            
                    "created": d}])
            self.response.headers['Content-Type'] = "application/json"
            self.response.out.write(j)
        else:
            self.redirect("/")

class NewPost(Handler):
    def get(self):
        user = login_check(self)    # see if user logged in
        if user:
            self.render_form()
        else:
            self.redirect('/login')
    def post(self):
        user = login_check(self)    # see if user logged in
        if user:
            subject = self.request.get("subject")
            content = self.request.get("content")
            if subject and content:
                e = Entry(subject = subject, content = content)
                e.put()
                top_entries(update=True)  # update front page entries in cache
                self.redirect('/')
            else:
                error = "we need both subject and content!"
                self.render_form(subject, content, error)
        else:
            self.redirect('/login')
    def render_form(self, subject="", content="", error=""):
        self.render("addForm.html", subject=subject, content=content,   
                error=error)

###########################
### Blog-specific code end
###########################


###############################
### User management code start
###############################

def hash_str(s):
    s = str(s)
    return hmac.new(SECRET, s).hexdigest()
    
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)
    
def make_salt():
    salt = ''.join(random.choice(string.letters) for x in xrange(5))
    return salt

class User(db.Model):
    username = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    hashy = db.StringProperty(required = True)

class SignupPage(Handler):
    def get(self):
        self.render("signupForm.html", username="", usernameError="", 
                password="", passwordError="", verify="", verifyError="",
                email="", emailError="")
        
    def post(self):
        username = self.request.get("username")
        
        if not USER_RE.match(username) or not username:
            usernameError = "Bad username"
        else:
            # see if it's already in database
            entries = db.GqlQuery(
                    "select * from User where username = :1", username)
            if entries.count() > 0:
                usernameError = "username taken"
            else:
                usernameError = ""
            
        password = self.request.get("password")
        if not PASSWORD_RE.match(password) or not password:
            passwordError = "Not a valid password"
            password = ""
        else:
            passwordError = ""
        
        verify = self.request.get("verify")
        if verify != password:
            verifyError = "Passwords didn't match"
            verify = ""
            password = ""
        else:
            verifyError = ""
        
        email = self.request.get("email")
        if email and not EMAIL_RE.match(email):
            emailError = "Invalid email"
        else:
            emailError = ""
        
        if (not usernameError and not passwordError and not verifyError and     
                not emailError):
            # create hash for this user
            h = make_pw_hash(username, password)
            hashy = h.split(",")[0]
            salt = h.split(",")[1]
            
            # add user info to db
            new_user = User(username=username, salt=salt, hashy=hashy)
            new_user.put()
            
            # create cookie
            new_id = new_user.key().id()
            hashy2 = hash_str(new_id)
            cookie = str(new_id) + "|" + hashy2
            
            # write cookie to browser
            self.response.headers.add_header('Set-Cookie',
                    'userID=%s; Path=/' % str(cookie))          
            
            # redirect to main blog page
            self.redirect("/")
        else:
            self.render("signupForm.html", username=username, 
                usernameError=usernameError, password=password, 
                passwordError=passwordError, verify=verify, 
                verifyError=verifyError, email=email, emailError=emailError)

class LoginPage(Handler):
    def get(self):
        self.render("loginForm.html", error="")
        
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        error = ""
        
        if (not USER_RE.match(username) or not username or not  
                PASSWORD_RE.match(password) or not password):
            self.print_error()
        else:
            # see if login info is valid
            entry = db.GqlQuery("select * from User where username = :1", 
                    username)
            if entry.count() > 0: # it at least exists
                entry = entry[0]
                #test if password correct
                salt = entry.salt
                h = make_pw_hash(username, password, salt).split(",")[0]
                if h == entry.hashy:  # login info valid, so write cookie
                    # create cookie
                    uid = entry.key().id()  # get db ID for this user
                    hmac_hash = hash_str(uid)
                    cookie = str(uid) + "|" + hmac_hash

                    # write cookie to browser
                    self.response.headers.add_header('Set-Cookie',
                            'userID=%s; Path=/' % str(cookie))          
                    
                    # redirect to main blog page
                    self.redirect("/")
                else:
                    self.print_error()
            else:
                self.print_error()
                
    def print_error(self):
        error = "Invalid login"
        self.render("loginForm.html", error=error)
    
class LogoutPage(Handler):
    def get(self):
        #clear cookie
        self.response.headers.add_header('Set-Cookie', 'userID=; Path=/')
        
        self.redirect("/")
                
class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        # get the cookie
        c = self.request.cookies.get('userID')
        if c:
            #check whether cookie info is correct
            h = c.split('|')[1]     # pull hash out of cookie
            ident = c.split('|')[0]     # pull id out of cookie
            h2 = hash_str(ident)
            if h == h2: # it's legit
                user = User.get_by_id(int(ident))   # grab user from database
                self.response.out.write("Welcome %s!" % user.username)
            else:
                self.redirect("signup")
        else:
            self.redirect("signup")
            

#############################
### User management code end
#############################

class FlushCache(webapp2.RequestHandler):
    def get(self):
        memcache.flush_all()
        self.redirect("/")

app = webapp2.WSGIApplication([('/', Blog), 
                               ('/.json', BlogJSON),
                               ('/newpost', NewPost),
                               ('/([0-9]+)', Permalink),
                               ('/deletePost/([0-9]+)', DeletePost),
                               ('/([0-9]+).json', PermalinkJSON),
                               ('/signup', SignupPage),
                               ('/login', LoginPage),
                               ('/logout', LogoutPage),
                               ('/welcome', WelcomeHandler),
                               ('/flush', FlushCache)
                               ], debug=True)
