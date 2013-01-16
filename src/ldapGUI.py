#!/usr/bin/env python

from common import *
from utils import *
from user import User
from group import Group
from setup import Setup
from sudo import Sudo
from host import Host
import ldapurl
from datetime import datetime


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
	
	def extend_session(self,how_much=600,_dc=None):
		if not logged_in():
			return "{failure:1}"
		return "{success:1}"
		
	extend_session = True
	
	def get_session(self,_dc=None):
		out='success'
		try:
			t = cherrypy.session['time']
		except:
			t = 0
			out='failure'
		cherrypy.response.headers['Content-Type'] = "text/plain"		
		d = datetime.fromtimestamp(t+600)
		hdate = d.strftime('%H:%M:%S')
		
		return "{%s:1,now:'%s',session_started:'%s',session_end:'%s',hsession_end:'%s'}" % (out,time(),t,t+600,hdate)
	
	get_session.exposed=True
	
	def Test(self, *args, **kwargs):
		x = cherrypy.url()
		return x
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
			do_redirect('/index')
		
		if username == "admin":
			username = "cn=Directory Manager"
		elif not "=" in username:
			username="uid=%s,ou=People,%s" % (username, suffix)
		
		use_SSL=0
		
		if ldapurl.isLDAPUrl(server):
			u = ldapurl.LDAPUrl(server)
			if u.urlscheme == "ldaps": use_SSL=1
			server = u.hostport
			
		if ":" in server:
			server,port = server.split(":")
			port = int(port)
		else:
			if use_SSL:
				port = 636
			else:
				port = 389

		if use_SSL:
			return """{failure:1,'info':"Unfortunately SSL is not supported at the moment"}"""
		try:
			l = ldap.open(server,port)
		except ldap.LDAPError, e:
			err = parse_ldap_error(e)
			return """{failure:1,'info':"%s"}""" % (err)
		
		try:
			l.simple_bind_s(username, password)
		except ldap.LDAPError, e:
			err = parse_ldap_error(e)
			return """{failure:1,'info':"%s"}""" % (err)
		
		l.unbind_s()
		
		if not "=" in suffix:
			x = suffix.split(".")
			suffix=''
			for a in x:
				suffix+="dc="+a+","
			# remove last ","
			suffix=suffix[:-1]
			
		suffix = suffix.replace(" ", "")	
		data={'server':server,'port':port,'username':username,'password':password,'suffix':suffix,'ssl':use_SSL}
		init_session(data)
		
		dnOk=False
		for x in do_ldap_search("objectclass=domain",['dn']):
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
configFile=os.path.join(baseDir, "conf/ldapGUI.conf")
if not os.path.exists(configFile):
	configFile=""


if len(sys.argv) < 2:
	cherrypy.quickstart(Root(), config=configFile)
elif sys.argv[1] == '-W':
	from flup.server.fcgi import WSGIServer
	app = cherrypy.tree.mount(Root(), config=configFile)
	cherrypy.config.update({'engine.autoreload_on':False}) 
	WSGIServer(app).run()
elif sys.argv[1] == '-D':
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0)
	except OSError, e:
		sys.stderr.write('Fork failed')
		sys.exit(1)
	os.chdir("/")
	os.umask(0)
	os.setsid()
	
	so = file(os.path.join(baseDir,"logs/ldapgui.log"), 'a+')
	si = file("/dev/null","r")
	os.dup2(si.fileno(), sys.stdin.fileno())
	os.dup2(so.fileno(), sys.stdout.fileno())
	os.dup2(so.fileno(), sys.stderr.fileno())

	# save pid
	f = file("/tmp/ldapgui.pid", "w")
	f.write("%s" % (os.getpid()))
	f.close()

	cherrypy.quickstart(Root(), config=configFile)
else:
	print "Unknown Option"
	sys.exit(0)

sys.exit(0)

