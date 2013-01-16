#!/usr/bin/env python

import os
import sys
import cherrypy
from mako.template import Template
from mako.lookup import TemplateLookup
import ldap
from config import *

try:
	import psyco
	psyco.full()
except:
	print "Psyco not installed"

baseDir=os.getcwd()
templatesDir=os.path.join(baseDir, "templates")
mylookup = TemplateLookup(directories=[templatesDir], 
	default_filters=['decode.latin1'],
	encoding_errors='replace',
	input_encoding='latin1',output_encoding='latin1')

def getTemplate(name):
	try:
		mytemplate = mylookup.get_template(name)
	except:
		return None

	return mytemplate


