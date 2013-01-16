import cherrypy
from config import *
from utils import *
from common import *


class Krb5(object):
    def index(self, *args, **kwargs):
        t = getTemplate('krb5.htpl')
        return t.render()
    
    def add(self, *args, **kwargs):
        return "{'success':1,'info':'Principal %s added successfully'}" % (kwargs['principal'])
    index.exposed=True
    add.exposed=True