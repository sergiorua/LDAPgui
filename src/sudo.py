""" SAMPLE ENTRY
# /etc/sudoers:
  # Allow all commands except shell
  johnny  ALL=(root) ALL,!/bin/sh
  # Always allows all commands because ALL is matched last
  puddles ALL=(root) !/bin/sh,ALL

  # LDAP equivalent of Johnny
  # Allows all commands except shell
  dn: cn=role1,ou=Sudoers,dc=my-domain,dc=com
  objectClass: sudoRole
  objectClass: top
  cn: role1
  sudoUser: johnny
  sudoHost: ALL
  sudoCommand: ALL
  sudoCommand: !/bin/sh
"""

import ldap
import ldap.modlist as modlist
import cherrypy
from config import *
from utils import do_ldap_search,parse_ldap_error


class Sudo(object):
    def list(self, *args, **kwargs):
        cn="*"
        if kwargs.has_key('cn'):
            cn=kwargs['cn']
        results = do_ldap_search("(&(objectclass=sudoRole)(cn=%s))" % (cn))

        output = "{results:["
        for res in results:
            res = res[0][1]
            commands=''
            sudouser=''
            sudooptions=''
            if res.has_key('sudoCommand'):
                commands=";".join(res['sudoCommand'])
            if res.has_key('sudoUser'):
                sudouser = res['sudoUser'][0]
            if res.has_key('sudoOption'):
                sudooptions=";".join(res['sudoOption'])
                

            hosts=";".join(res['sudoHost'])
            output += """{sudorole:"%s",sudouser:"%s",sudohost:"%s",sudocommands:"%s",sudooptions:"%s"},""" % (res['cn'][0],sudouser,hosts,commands,sudooptions)
            
        output += "]}"
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return output
    
    def index(self):
        return self.list()

    def add(self, role=None,sudohost=None,sudouser=None,sudogroup=None,sudocommands=None,sudooptions=None,_dc=None):

        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        if not server or not suffix or not adminUser or not adminPass:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation: you are not logged in or your session has expired'}"
        
        if sudogroup and not "Select" in sudogroup:
            sudouser="%%%s" % (sudogroup)
            
        commands=[]
        for c in sudocommands.split(";"):
            if len(c)>1:
                commands.append(c)
        Options=[]
        for c in sudooptions.split(";"):
            if len(c)>1:
                Options.append(c)
        
        attrs={'cn':role,'objectClass': ['top','sudoRole']}
        if len(sudouser)>0:
            attrs['sudoUser'] = sudouser
        if len(commands)>0:
            attrs['sudoCommand'] = commands
        if len(Options)>0:
            attrs['sudoOption'] = Options

        hosts=[]
        for c in sudohost.split(","):
            if len(c)>1:
                hosts.append(c)

        if len(hosts)<1:
            hosts.append("ALL")
        attrs['sudoHost']=hosts
        
         
        DN="cn=%s,ou=SUDOers,%s" % (role, suffix)
        
        if not server or not suffix: return "{'failure':1,'info':'Missing server or suffix'}"
        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{failure:1,info:"%s"}""" % (err)

        print "Adding\n\n"
        print attrs
        print "\n\n"
        try:
            l.add_s(DN, modlist.addModlist(attrs))
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{failure:1,info:"%s"}""" % (err)

        l.unbind_s()
        
        return "{'success':1,'info':'Role %s added successfully'}" % (role)
    
    def delete(self, sudorole=None, _dc=None):
        if not sudorole: return "{'failure':1,'info':'Role not found'}"
        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        
        if not server or not suffix or not adminUser or not adminPass:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation'"
        
        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{failure:1,info:"%s"}""" % (err)

        deleteDN='cn=%s,ou=SUDOers,%s' % (sudorole,suffix)
        
        try:
            l.delete_s(deleteDN)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{failure:1,info:"%s"}""" % (err)

        l.unbind_s()
        
        return "{'success':1,'info':'Role %s deleted successfully',role:'%s'}" % (sudorole,sudorole)

    def get(self, sudorole=None,_dc=None):
        results = do_ldap_search("(&(objectclass=SudoRole)(cn=%s))" % (sudorole))

        if not results:
            return "{}"
        res=results[0][0][1]

        users=''
        hosts=''
        commands=''
        options=''
        if res.has_key('sudoUser'):
            users = ';'.join(res['sudoUser'])
        if res.has_key('sudoCommand'):
            commands = ';'.join(res['sudoCommand'])
        if res.has_key('sudoHost'):
            hosts = ';'.join(res['sudoHost'])
        if res.has_key('sudoOption'):
            options = ';'.join(res['sudoOption'])
        output = """{cn:"%s",sudoCommand:"%s",sudoUser:"%s",sudoHost:"%s",sudoOption:"%s"}""" % (sudorole,commands,users,hosts,options)
            
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return output
    
    def update(self, role=None,sudohost=None,sudouser=None,sudogroup=None,sudocommands=None,sudooptions=None,_dc=None):
        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        
        if not server or not suffix or not adminUser or not adminPass:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation'"

        sudorole=role
        results = do_ldap_search("(&(objectclass=SudoRole)(cn=%s))" % (sudorole))

        if not results:
            return "{failure:1,info:'Role not found'}"
        DN=results[0][0][0]
        res=results[0][0][1]

        if sudogroup and not "Select" in sudogroup:
            if "%" in sudogroup:
                sudouser="%s" % (sudogroup)
            else:
                sudouser="%%%s" % (sudogroup)

        if "Select" in sudouser:
            sudouser=''
        commands=[]
        for c in sudocommands.split(";"):
            if len(c)>1:
                commands.append(c)

        hosts=[]
        for c in sudohost.split(","):
            if len(c)>1:
                hosts.append(c)
        options=[]
        for c in sudooptions.split(";"):
            if len(c)>1:
                options.append(c)        
        
        Current={'cn':res['cn']}
        for k in ["sudoCommand", "sudoUser", "sudoOption","sudoHost"]:
            if res.has_key(k):
                Current[k] = res[k]

        New={'cn':role}
        if len(sudouser)>0:
            New['sudoUser'] = sudouser
        if len(commands)>0:
            New['sudoCommand'] = commands
        if len(options)>0:
            New['sudoOption'] = options
        
        if len(hosts)>0:
            New['sudoHost'] = hosts
        else:
            New['sudoHost'] = 'ALL'

        
        print "\n\n"
        print Current
        print "\n\n"
        print New
        print "\n\n"
        
        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{failure:1,info:"%s"}""" % (err)
                
        try:
            l.modify_s(DN, modlist.modifyModlist(Current, New))
        except ldap.LDAPError, e:
            l.unbind_s()
            err = parse_ldap_error(e)
            return """{failure:1,info:"%s"}""" % (err)
        
        l.unbind_s()
        
        return "{success:1,info:'Role %s updated successfully'}" % (role)

    index.exposed=True
    add.exposed=True
    list.exposed=True
    delete.exposed=True
    get.exposed=True
    update.exposed=True