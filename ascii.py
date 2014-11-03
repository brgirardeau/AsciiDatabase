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

def validLogin(username, password):
	return 1

def validSignUp(username, password, passwordTwo):
	return 1

class User(webapp2_extras.appengine.auth.models.User):
	def set_password(self, raw_password):
		"""Sets the password for the current user
 
    	:param raw_password:
       		The raw password which will be hashed and stored
   		"""
		self.password = security.generate_password_has(raw_password, length=12)
	def get_by_auth_token(cls, user_id, token, subject='auth'):
	    """Returns a user object based on a user ID and token.
	 
	    :param user_id:
	        The user_id of the requesting user.
	    :param token:
	        The token string to be verified.
	    :returns:
	        A tuple ``(User, timestamp)``, with a user object and
	        the token timestamp, or ``(None, None)`` if both were not found.
	    """
	    token_key = cls.token_model.get_key(user_id, subject, token)
	    user_key = ndb.Key(cls, user_id)
	    # User get_multi() to save a RPC call.
	    valid_token, user = ndb.get_multi([token_key, user_key])
	    if valid_token and user:
	    	timestamp = int(time.mktime(valid_token.created.timetuple()))
	    	return user, timestamp
	    return None, None

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
 
  def render_template(self, view_filename, params=None):
  	if not params:
  		params={}
	user = self.user_info
	params['user'] = user
	path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
	self.response.out.write(template.render(path, params))
 
  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('message.html', params)
 
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

class SignupHandler(BaseHandler):
	def get(self):
		template = JINJA_ENVIRONMENT.get_template('templates/signup.html')
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
	          They will be able to do so by visiting  <a href="{url}">{url}</a>'
	 
	    self.display_message(msg.format(url=verification_url))

class LoginHandler(BaseHandler):
	def get(self):
		template = JINJA_ENVIRONMENT.get_template('templates/signin.html')
		self.response.write(template.render())

	def post(self):
		username = self.request.get('Username')
		password = self.request.get('Password')
		try:
			u = self.auth.get_user_by_password(username, password, remember=True)
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
		self.redirect(self.uri_for('home'))

class HomePage(webapp2.RequestHandler):
	def get(self):
		self.response.headers['content-type']='text/html'
		template = JINJA_ENVIRONMENT.get_template('templates/homepage.html')
		self.response.write(template.render())

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

class WelcomePage(webapp2.RequestHandler):
	def get(self):
		self.response.headers['content-type']='text/html'
		template = JINJA_ENVIRONMENT.get_template('templates/welcome.html')
		global username
		template_values = {"username": username}
		self.response.write(template.render(template_values))

class ProfilePage(webapp2.RequestHandler):
	def get(self):
		self.response.headers['content-type']='text/html'
		template = JINJA_ENVIRONMENT.get_template('templates/profilepage.html')
		self.response.write(template.render()) 

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['email']
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
], debug=True)