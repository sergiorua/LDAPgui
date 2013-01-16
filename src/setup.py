from common import *
from utils import *
from config import *
import os

class Setup(object):
    def index(self):
        if not logged_in():
            raise cherrypy.HTTPRedirect('/login?msg=You are not logged in')
        t = getTemplate('setup.htpl')
        return t.render(server=cherrypy.session['server'],suffix=cherrypy.session['suffix'])
    
    def save(self, server="127.0.0.1", suffix=None,adminuser="cn=Directory Manager",password=None,password2=None,_dc=None):

        if not "=" in suffix:
            x = suffix.split(".")
            suffix=''
            for a in x:
                suffix+="dc="+a+","
            # remove last ","
            suffix=suffix[:-1]
                
                
        cmd = "echo '%s' | %s create-suffix -h %s -D '%s' -c '%s'" % (defaultAdminPass,
                                                      dsconf,
                                                      server,
                                                      defaultAdminUser,
                                                      suffix) 
        try:
            print "=====>>> " + cmd
            #ret = os.system(cmd)
        except:
            return "{failure:1,'info':'Domain creation failed!'}"
        
        if int(ret) > 0:
            print "ERROR: " + str(ret)
            return "{failure:1,'info':'Domain creation failed!'}"
        
        return "{success:1,'info':'Configuration saved'}"
    
    index.exposed = True
    save.exposed=True