import webapp2
import jinja2
import os
import os.path
from google.appengine.ext import ndb
import webapp2_extras.appengine.auth.models #for user authentication
from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError
import time
import logging

JINJA_ENVIRONMENT = jinja2.Environment(
	loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
	extensions=['jinja2.ext.autoescape'])

# def validLogin(username, password):
# 	return 1

# def validSignUp(username, password, passwordTwo):
# 	return 1

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
 
  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    template = JINJA_ENVIRONMENT.get_template('templates/message.html')
    self.response.write(template.render(params))

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

class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']
 
    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
      'signup')
 
    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)
      self.abort(404)
 
    # store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
 
    if verification_type == 'v':
      # remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)
 
      if not user.verified:
        user.verified = True
        user.put()
 
      self.display_message('User email address has been verified.')
      return
    elif verification_type == 'p':
      # supply user to the page
      params = {
        'user': user,
        'token': signup_token
      }
      template = JINJA_ENVIRONMENT.get_template('templats/resetpassword.html')
      self.response.write(template.render(params))
    else:
      logging.info('verification type not supported')
      self.abort(404)

class SignupHandler(BaseHandler):
  def get(self):
    template = JINJA_ENVIRONMENT.get_template('/templates/signup.html')
    self.response.write(template.render())

  def post(self):
    user_name = self.request.get('Username')
    email = self.request.get('Email')
    password = self.request.get('Password')
    passwordTwo = self.request.get('PasswordTwo')

    unique_properties = ['email_address']
    user_data = self.user_model.create_user(user_name,
      unique_properties,
      email_address=email, password_raw=password,
      verified=False)
    if not user_data[0]: #user_data is a tuple
      self.display_message('Unable to create user for email %s because of \
        duplicate keys %s' % (user_name, user_data[1]))
      return
    
    user = user_data[1]
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='v', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to verify their address. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

    self.display_message(msg.format(url=verification_url))

class SetPasswordHandler(BaseHandler):

  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    
    self.display_message('Password updated')

class ForgotPasswordHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')

    user = self.user_model.get_by_auth_id(username)
    if not user:
      logging.info('Could not find any user entry for username %s', username)
      self._serve_page(not_found=True)
      return

    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='p', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to reset their password. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

    self.display_message(msg.format(url=verification_url))
  
  def _serve_page(self, not_found=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'not_found': not_found
    }
    template = JINJA_ENVIRONMENT.get_template('/templates/forgot.html')
    self.response.write(template.render(params))

class LoginHandler(BaseHandler):
	def get(self):
		template = JINJA_ENVIRONMENT.get_template('templates/signin.html')
		self.response.write(template.render())

	def post(self):
		username = self.request.get('Username')
		password = self.request.get('Password')
		try:
			u = self.auth.get_user_by_password(username, password, remember=True, save_session=True)
			self.redirect('/welcome')
		except (InvalidAuthIdError, InvalidPasswordError) as e:
			logging.info('Login failed for user %s because of %s', username, type(e))
			self._serve_page(True)

		def _serve_page(self, failed=False):
			username = self.request.get('Username')
			params = {
				'username':username,
				'failed':failed
			}
			template = JINJA_ENVIRONMENT.get_template('templates/signin.html')
			self.response.write(template.render(params))

class LogoutHandler(BaseHandler):
	def get(self):
		self.auth.unset_session()
		self.redirect('/')

class HomePage(BaseHandler):
	def get(self):
		template = JINJA_ENVIRONMENT.get_template('templates/homepage.html')
		self.response.write(template.render())

class AuthenticatedHandler(BaseHandler):
  @user_required
  def get(self):
  	self.redirect('/welcome')

# class SignUpPage(webapp2.RequestHandler):
# 	def get(self):
# 		self.response.headers['content-type']='text/html'
# 		template = JINJA_ENVIRONMENT.get_template('templates/signup.html')
# 		self.response.write(template.render())
# 	def post(self):
# 		global username
# 		username = self.request.get("Username")
# 		password = self.request.get("Password")
# 		passwordTwo = self.request.get("PasswordTwo")
# 		if validSignUp(username, password, passwordTwo):
# 			self.redirect('/welcome')

# class SignInPage(webapp2.RequestHandler):
# 	def get(self):
# 		self.response.headers['content-type']='text/html'
# 		template = JINJA_ENVIRONMENT.get_template('templates/signin.html')
# 		self.response.write(template.render())
# 	def post(self):
# 		username = self.request.get("Username")
# 		password = self.request.get("Password")
# 		if validLogin(username, password):
# 			self.redirect('/profile')

class WelcomePage(BaseHandler):
	def get(self):
		self.response.headers['content-type']='text/html'
		template = JINJA_ENVIRONMENT.get_template('templates/welcome.html')
		global username
		template_values = {"username": username}
		self.response.write(template.render(template_values))

class ProfilePage(BaseHandler):
	def get(self):
		self.response.headers['content-type']='text/html'
		template = JINJA_ENVIRONMENT.get_template('templates/profilepage.html')
		self.response.write(template.render()) 

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}

application = webapp2.WSGIApplication([
	('/', HomePage),
	('/signup', SignupHandler),
	('/signin', LoginHandler),
	('/profile', ProfilePage),
	('/welcome', WelcomePage),
	webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
  handler=VerificationHandler, name='verification')
], debug=True)