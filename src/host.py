import ldap
import ldap.modlist as modlist
import cherrypy
from config import *
from utils import do_ldap_search,parse_ldap_error


class Host(object):
    def list(self, *args, **kwargs):
        cn="*"
        if kwargs.has_key('cn'):
            cn=kwargs['cn']
        results = do_ldap_search("(&(objectclass=ipHost)(cn=%s))" % (cn))

        output = "{results:["
        for res in results:
            if "ipHostNumber" in res[0][0]:
                hostname = res[0][0].split("+")[0].replace("cn=","")

            res = res[0][1]
            aliases=";".join(res['cn'])
            output += """{hostname:"%s",ip:"%s",aliases:"%s"},""" % (hostname,res['ipHostNumber'][0],aliases)
            
        output += "]}"
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return output
    
    
    def add(self, hostname=None,ip=None,aliases=None,_dc=None):

        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        if not server or not suffix or not adminUser or not adminPass:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation'"
        
        if not hostname or not ip:
            return "{failure:1,'info':'Hostname or IP address missing'"
        
        if "ie:" in aliases: aliases=''
        hostAliases=[]
        for c in aliases.split(","):
            if len(c)>1:
                c = c.replace(" ","")
                hostAliases.append(c)
        hostAliases.append(hostname)

        attrs={
               'cn':hostAliases,
               'objectClass': ['top','ipHost','device'],
               'ipHostNumber':ip,
               }
            
        DN="cn=%s+ipHostNumber=%s,ou=Hosts,%s" % (hostname,ip,suffix)
        
        
        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return "{'failure':1,'info':'%s'}" % (err)

        print "Adding\n\n"
        print attrs
        print "\n\n"
        try:
            l.add_s(DN, modlist.addModlist(attrs))
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return "{'failure':1,'info':'%s'}" % (err)
        l.unbind_s()
        
        return "{'success':1,'info':'Host %s added successfully'}" % (hostname)
    
    def delete(self, hostname=None,ip=None,aliases=None,_dc=None):
        if not hostname or not ip: return "{'failure':1,'info':'Host not found'}"
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
            return "{failure:1,'info':'%s'}" % (err)

        if ip and hostname:
            deleteDN='cn=%s+ipHostNumber=%s,ou=Hosts,%s' % (hostname,ip,suffix)
        
        try:
            l.delete_s(deleteDN)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{failure:1,info:"%s"}""" % (err)

        l.unbind_s()
        
        return "{success:1,info:'Host %s deleted successfully',hostname:'%s'}" % (hostname,hostname)
    

    def get(self, hostname=None,ip=None,_dc=None):
        if not ip is None:
            results = do_ldap_search("(&(objectclass=ipHost)(ipHostNumber=%s))" % (ip))
        else:
            results = do_ldap_search("(&(objectclass=ipHost)(cn=%s))" % (hostname))

        if not results:
            return "{}"
        res=results[0][0][1]

        output = ""
        if "ipHostNumber" in results[0][0]:
            hostname = results[0][0].split("+")[0].replace("cn=","")

        aliases=",".join(res['cn'])
        output += """{hostname:"%s",ip:"%s",aliases:"%s"}""" % (hostname,res['ipHostNumber'][0],aliases)
            
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return output

    def update(self, hostname=None,ip=None,aliases=None,_dc=None):
        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        
        if not server or not suffix or not adminUser or not adminPass:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation'"
    
        if not hostname or not ip:
            return "{failure:1,'info':'Nothing to change'"
        results = do_ldap_search("(&(objectclass=ipHost)(cn=%s))" % (hostname))

        if len(results) < 1:
            return "{failure:1,'info':'Cannot find the required host'}"
        
        DN=results[0][0][0]
        res=results[0][0][1]
        if "ie:" in aliases: aliases=''

        hostAliases=[]
        for c in aliases.split(","):
            if len(c)>1:
                c = c.replace(" ","")
                hostAliases.append(c)
        if not hostname in hostAliases:
            hostAliases.append(hostname)
        
        Current={"cn":res['cn'],"ipHostNumber":res['ipHostNumber'][0]}
        New={"cn":hostAliases,"ipHostNumber":ip}
        
        if Current == New:
            return "{success:1,info:'No changes needed'}"
        
        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return "{failure:1,'info':'Bind: %s'}" % (err)
                
        try:
            l.modify_s(DN, modlist.modifyModlist(Current, New))
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return "{failure:1,'info':'%s'}" % (err)
        
        l.unbind_s()
        
        return "{success:1,'info':'Host %s updated'}" % (hostname)
        
        
    add.exposed=True
    list.exposed=True
    delete.exposed=True    
    get.exposed=True
    update.exposed=True
