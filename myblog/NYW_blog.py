import os
import re
import random
import hashlib
import hmac
import datetime
import webapp2
from string import letters

# import jinja2 lib for templating
import jinja2

# import google app engine data store lib
from google.appengine.ext import db
from google.appengine.ext.db import metadata

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = '!dwsg#@kjsdc&*vs&)~#'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# class MainPage(BlogHandler):
#   def get(self):
#       self.write('Hello, Udacity!')


##### user portion

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog portion

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    author_name = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

class BlogFront(BlogHandler):
    def get(self):
        # posts = greetings = Post.all().order('-created')
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        self.render('permalink.html', post = post)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            self.redirect('/')

        author_name = self.user.name
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), 
                     author_name = self.user.name, 
                     subject = subject, 
                     content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render('newpost.html', subject=subject, content=content, error=error)

###### Unit 2 HW's

class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')
        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{5,20}$")
def valid_password(password):
    return password and PASS_RE.match(password) 

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render('signup-form.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = " Invalid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = " Invalid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = " Passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = " Invalid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()
            # self.redirect('/welcome')

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = ' User already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/welcome')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')





class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Posts', int(post_id), parent = blog_key())
        p = db.get(key)

        if post.user_id == self.user.key().id():
            self.render("editpost.html", subject=p.subject, content=p.content)
        else:
            error = "You need to be logged in to edit your post!"
            self.render('login-form.html', error=error)

    def post(self):
        if not self.user:
            self.redirect("/")

        subject = self.request.get("subject")
        content = self.request.get("content")
        author = self.user.name

        if subject and content:
            p = Posts(parent = blog_key(), author=author, subject=subject, content=content)
            p.put()
            self.redirect("/blog/%s" % str(p.key().id()))
        else:
            error = "You have to fill in both subject and content fields!"
            self.render("editpost.html", subject=subject, content=content, error=error)

# class EditPost(BlogHandler):
#     """ Handles the editing of blog posts """
#     def get(self):
#         """ uses get request to get newpost.html """
#         post_id = self.request.get('post_id')
#         key = db.Key.from_path('Post',
#                                int(post_id),
#                                parent=blog_key())
#         # gets the post data based upon what
#         # is passed from post_id into key
#         post = db.get(key)
#         if self.read_secure_cookie('usercookie'):
#             user_id = self.read_secure_cookie('usercookie')
#             # If the current logged in user is not the post author
#             # it redirects them back to the previous page
#             if post_id == post.author_id:
#                 self.render("editpost.html",
#                             subject=post.subject,
#                             content=post.content,
#                             post_id=post_id)
#             else:
#                 referrer = self.request.headers.get('referer')
#                 if referrer:
#                     return self.redirect(referrer)
#                 return self.redirect_to('/')
#         else:
#             self.redirect('/signup')

    # def get(self, post_id):

    #     # Retrieve all blog posts
    #     posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")

    #     key = db.Key.from_path('Post', int(post_id)), parent=blog_key())
    #     post = db.get(key)
    #     if post.user_id == self.user.key().id():
    #         self.render("editpost.html", title=post.title,
    #                     content=post.content)
    #     else:
    #         error = "You do not have access to edit this post."
    #         self.render("post.html", author_name = self.user.name,
    #                 posts=posts, error=error)

    #  def post(self, post_id):
    #     title = self.request.get('title')
    #     content = self.request.get('content')

    #     key = db.Key.from_path('Post', int(post_id))
    #     post = db.get(key)

    #     if post.user_id == self.user.key().id():
    #         if title and content:
    #             key = db.Key.from_path('Post', int(post_id))
    #             post = db.get(key)
    #             if post:
    #                 post.title = title
    #                 post.content = content
    #                 post.put()
    #                 self.redirect('/post/%s' % post_id)
    #             else:
    #                 error = "This post does not exist."
    #                 self.render("post.html", author_name = self.user.name,
    #                 posts=posts, error=error)
    #         else:
    #             error = "You need both a title and some content to update a post."
    #             self.render("editpost.html", title=title,
    #                         content=content, error=error)
    #     else:
    #             error = "You do not have access to edit this post."
    #             self.render("post.html", author_name = self.user.name,
    #                 posts=posts, error=error)
                               

app = webapp2.WSGIApplication([('/?', BlogFront),
                               ('/rot13', Rot13),
                               ('/blog/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/editpost', EditPost),
                               ],
                              debug=True)
