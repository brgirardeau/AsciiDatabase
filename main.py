#!/usr/bin/env python

import jinja2
from google.appengine.ext.webapp import template
from google.appengine.ext import db

import logging
import os.path
import webapp2
import time

from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

def guess_autoescape(template_name):
    if template_name is None or '.' not in template_name:
        return False
    ext = template_name.rsplit('.', 1)[1]
    return ext in ('html', 'htm', 'xml')

JINJA_ENVIRONMENT = jinja2.Environment(
    autoescape=guess_autoescape,     ## see http://jinja.pocoo.org/docs/api/#autoescaping
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'])

def escape_html(s):
   return cgi.escape(s, quote = True)

def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.

    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.

    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """    
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    template = JINJA_ENVIRONMENT.get_template(filename)
    self.response.write(template.render(params))

  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('templates/message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)
    ## saves you from having to type self.response.out.write
  def write(self, a):            
      self.response.out.write(a)
  
  ## takes a template and dictionary and returns a string with the rendered template
  def render_str(self, template, **params): 
    template = JINJA_ENVIRONMENT.get_template('templates/'+template)
    return template.render(params)

  ## takes a template and dictionary and writes the rendered template
  def render(self, template, **kw):
      self.write(self.render_str(template, **kw))

class MainHandler(BaseHandler):
  def get(self):
    self.render_template('templates/homepage.html')

class SignupHandler(BaseHandler):
  def get(self):
    self.render_template('templates/signup.html')

  def post(self):
    user_name = self.request.get('Username')
    email = self.request.get('Email')
    password = self.request.get('Password')
    passwordTwo = self.request.get('PasswordTwo')
    user_data = self.user_model.create_user(user_name,
      unique_properties=[], 
      username = user_name, email_address=email, password_raw=password,
      verified=False)
    if not user_data[0]: #user_data is a tuple
      self.display_message('Unable to create user for email %s because of \
        duplicate keys %s' % (user_name, user_data[1]))
      return
    self.redirect('/welcome')

class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('Username')
    password = self.request.get('Password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True,
        save_session=True)
      self.redirect('/profile')
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('Username')
    if failed:
      message = "Either the username or password is incorrect."
    else:
      message = ""
    params = {
      'Username': username,
      'failed': message
    }
    self.render_template('templates/signin.html', params)

class Art(db.Model):
   title = db.StringProperty()  
   art = db.TextProperty()
   created = db.DateTimeProperty(auto_now_add = True)
   author = db.StringProperty()

class PublicFeedHandler(BaseHandler):
  @user_required
  def get(self, title="", art="", error=""):
      arts = db.GqlQuery("SELECT * FROM Art "
                         "ORDER BY created DESC ")
      arts = list(arts)
      self.render("feed.html", title=title, art=art, arts=arts)

class ProfileHandler(BaseHandler):
  @user_required
  def get(self):
    auth = self.auth
    user = auth.get_user_by_session()['username']
    arts = db.GqlQuery("SELECT * FROM Art WHERE author = '%s' ORDER BY created DESC" % user)
    self.render("profilepage.html", arts=arts)
  def post(self):
    title = self.request.get("title")
    art   = self.request.get("art")
    if title and art:
       a = Art(title=title,art=art)
       auth = self.auth
       user = auth.get_user_by_session()['username']
       logging.info(user)
       a.author = user
       a.put()
       time.sleep(0.2)
       self.redirect("/profile")

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('home'))

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['username']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}

app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route('/signin', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/profile', ProfileHandler),
    webapp2.Route('/feed', PublicFeedHandler),
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
