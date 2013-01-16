#!/usr/bin/env python

from common import *
from utils import *
from user import User
from group import Group
from setup import Setup
from sudo import Sudo
from host import Host
from krb import Krb5


#######################################################################
""" Error handlers """
Debug = 1

def handle_error():
	cherrypy.response.status = 500
	if Debug:
		cherrypy.response.headers['Content-Type'] = "text/plain"
		cherrypy.response.body = [ str(cherrypy._cperror.format_exc()) ]
	else:
		cherrypy.response.body = ["<html><body>Sorry, an error occured</body></html>"]

def error_404(status, message, traceback, version):
	return "Page not found"
		
#######################################################################

class Root(object):
	_cp_config = {'request.error_response': handle_error}
#	_cp_config = {'error_page.404': os.path.join(localDir, "errors/404.html")}

	
	user = User()
	group = Group()
	setup = Setup()
	sudo = Sudo()
	host = Host()
	krb = Krb5()
	
	def Test(self, *args, **kwargs):
		if kwargs.has_key('msg'):
			return kwargs['msg']
		return "%s" % (kwargs[0])
	Test.exposed = True
	
	def index(self, *args, **kwargs):
		if kwargs.has_key('msg'):
			msg = kwargs['msg']
		else:
			msg = "You are not logged in"
		if not logged_in():
			#raise cherrypy.HTTPRedirect('/login?msg=%s' % (msg))
			do_redirect('/login?msg=%s' % (msg))
		t = getTemplate('index.htpl')
		return t.render(server=cherrypy.session['server'],suffix=cherrypy.session['suffix'])

	def login(self, *args, **kwargs):
		
		if kwargs.has_key('msg'):
			msg = kwargs['msg']
		else:
			msg = "You are not logged in"
		
		t = getTemplate('login.htpl')
		return t.render(msg=msg)
	
	def logout(self, *args, **kwargs):
		doLogout()
		raise cherrypy.HTTPRedirect('/login')

	def doLogin(self, server=None,username=None,password=None,suffix=None,remember=True,_dc=None):
		if not username or not password:
			return "{'failure':1,'info':'Missing username or password'}"
		
		if logged_in():
			raise cherrypy.HTTPRedirect('/index')
		
		if username == "admin":
			username = "cn=Directory Manager"
			
		if ":" in server:
			server,port = server.split(":")
			port = int(port)
		else:
			port = 389
		try:
			l = ldap.open(server,port)
		except ldap.LDAPError, e:
			return """{failure:1,'info':"%s"}""" % (e[0]['info'])
		
		try:
			l.simple_bind_s(username, password)
		except ldap.LDAPError, e:
			return """{failure:1,'info':"%s"}""" % (e[0]['desc'])
		
		l.unbind_s()
		
		if not "=" in suffix:
			x = suffix.split(".")
			suffix=''
			for a in x:
				suffix+="dc="+a+","
			# remove last ","
			suffix=suffix[:-1]
			
		suffix = suffix.replace(" ", "")	
		data={'server':server,'port':port,'username':username,'password':password,'suffix':suffix}
		init_session(data)
		
		dnOk=False
		for x in do_ldap_search("objectclass=domain",['dn']):
			print x
			if x[0][0] == suffix:
				dnOk = True
		if not dnOk:
			destroy_session()
			return """{failure:1,'info':"Incorrect suffix or domain. Access denied."}"""
		
		if remember in "yes" "on":
			setCookie("server", server)
			setCookie("suffix", suffix)
			setCookie("adminUser", username)
		## raise cherrypy.HTTPRedirect(cherrypy.url('/index?msg=test'))
		return "{success:1,'info':'Login OK'}"
       
	index.exposed=True
	login.exposed=True
	doLogin.exposed=True
	logout.exposed=True


#######################################################################
if os.path.exists("conf/ldapGUI.conf"):
	configFile="conf/ldapGUI.conf"
else:
	configFile=""


cherrypy.quickstart(Root(), config=configFile)

sys.exit(0)

