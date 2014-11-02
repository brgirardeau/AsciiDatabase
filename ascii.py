import webapp2
import jinja2
import os
from google.appengine.ext import db

JINJA_ENVIRONMENT = jinja2.Environment(
	loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
	extensions=['jinja2.ext.autoescape'])

def validLogin(username, password):
	return 1

def validSignUp(username, password, passwordTwo):
	return 1

class HomePage(webapp2.RequestHandler):
	def get(self):
		self.response.headers['content-type']='text/html'
		template = JINJA_ENVIRONMENT.get_template('templates/homepage.html')
		self.response.write(template.render())
class SignUpPage(webapp2.RequestHandler):
	def get(self):
		self.response.headers['content-type']='text/html'
		template = JINJA_ENVIRONMENT.get_template('templates/signup.html')
		self.response.write(template.render())
	def post(self):
		global username
		username = self.request.get("Username")
		password = self.request.get("Password")
		passwordTwo = self.request.get("PasswordTwo")
		if validSignUp(username, password, passwordTwo):
			self.redirect('/welcome')

class SignInPage(webapp2.RequestHandler):
	def get(self):
		self.response.headers['content-type']='text/html'
		template = JINJA_ENVIRONMENT.get_template('templates/signin.html')
		self.response.write(template.render())
	def post(self):
		username = self.request.get("Username")
		password = self.request.get("Password")
		if validLogin(username, password):
			self.redirect('/profile')

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

application = webapp2.WSGIApplication([
	('/', HomePage),
	('/signup', SignUpPage),
	('/signin', SignInPage),
	('/profile', ProfilePage),
	('/welcome', WelcomePage),
], debug=True)