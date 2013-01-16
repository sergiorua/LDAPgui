import ldap
import ldap.modlist as modlist
import cherrypy
from utils import do_ldap_search, autoGen_gid,parse_ldap_error
import copy
from user import getUserCN, getUser, getUserUID
from config import *


def getGroupCN(gid):
    results = do_ldap_search("(&(objectclass=posixGroup)(gidNumber=%s))" % (gid),['cn'])
    if not results:
        return 0

    res=results[0][0][1]['cn'][0]
    return res
    
    
class Group(object):
    def add(self, groupName=None, gidNumber=None,members=None,_dc=None):
        
        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        if not server or not suffix or not adminUser or not adminPass:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation: you are not logged in or your session has expired'}"
        
        if not server or not suffix: return "{'failure':1,'info':'Missing server or suffix'}"
        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return "{'failure':1,'info':'%s'}" % (err)
    
        if not gidNumber or "Leave" in gidNumber:
            gidNumber = autoGen_gid()

        attrs = {'cn':groupName,
                 'gidNumber':str(gidNumber),
                 'objectclass':['top','posixGroup','groupOfUniqueNames'],
                 }
        if members:
            if len(members)>1:
                userMembers=[]
                uniqueMember=[]
                for user in members.split(","):
                    if len(user)>2:
                        full_user = "uid=%s,ou=People,%s" % (user, suffix)
                        userMembers.append(user)
                        uniqueMember.append(full_user)
                attrs['memberUid'] = userMembers
                attrs['uniqueMember'] = uniqueMember
        
        id='cn=%s,ou=Group,%s' % (groupName,suffix)
        try:
            l.add_s(id, modlist.addModlist(attrs))
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{failure:1,info:"%s"}""" % (err)

        l.unbind_s()

        return "{'success':1,'info':'Group %s added'}" % (groupName)
    add.exposed=True
    
    def delete(self,groupName=None,gidNumber=None,_dc=None):
        
        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        
        if not server or not suffix or not adminUser or not adminPass:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation'"
        
        if not groupName and not gidNumber: 
            return "{failure:1,'info':'Missing group name or GID'}"
        
        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return "{failure:1,'info':'%s'}" % (err)

        if not groupName:
            groupName=getGroupDN(gidNumber)
        if len(groupName) < 2:
            return "{failure:1,'info':'Cannot identified group'}"
        
        deleteDN='cn=%s,ou=Group,%s' % (groupName,suffix)
        
        try:
            l.delete_s(deleteDN)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return "{failure:1,'text':'%s'}" % (err)

        l.unbind_s()

        return """{success:1,'info':"Group %s deleted",group:"%s"}""" % (groupName,groupName)
    
    delete.exposed = True
    
    def list(self, server=None, suffix=None, searchFilter=None,_dc=None,query=None):
        
        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        if not server or not suffix or not adminUser or not adminPass:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation: you are not logged in or your session has expired'}"
        
        print "==> Loading groups list\n\n"
        l = ldap.open(server)
        try:
            # l.simple_bind_s(adminUser, adminPass)
            l.simple_bind_s()
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return "{'failure':1,'text':'%s'}" % (err)

        baseDN=suffix
        searchScope = ldap.SCOPE_SUBTREE
        if not searchFilter:
            searchFilter='(&(cn=*)(objectclass=posixGroup))'
        retrieveAttributes = None
        
        try:
            res_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return "{'failure':1,'info':'%s'}" % (err)

        results=[]
        while 1:
            result_type, result_data = l.result(res_id, 0)
            if result_data == []: break
            if result_type == ldap.RES_SEARCH_ENTRY:
                results.append(result_data)

        #return "{'success':'Got %s entries'}" % (len(results))
        output = "{results:["
        for res in results:
            res = res[0][1]
            members=''
            if res.has_key('memberUid'):
                for m in res['memberUid']:
                    #members+="%s|%s;" % (m, getUserCN(m))
                    members+="%s|%s;" % (getUserUID(username=m), m)
                
            output += """{name:"%s",gid:'%s',members:'%s'},""" % (res['cn'][0],res['gidNumber'][0],members)
                                             
        output += "]}"
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return output
    list.exposed = True

    def update(self, groupName=None, gidNumber=None,members=None,_dc=None):
        if not groupName:
            return "{failure:1,'text':'No group found'}"

        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        
        if not server or not suffix or not adminUser or not adminPass or not gidNumber:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation'"
    
        results = do_ldap_search("(&(objectclass=posixGroup)(cn=%s))" % (groupName))
        if len(results) < 1:
            return "{failure:1,'info':'Cannot find the required group'}"
        
        res=results[0][0][1]
        
        
        memberUid=[]
        uniqueMember=[]
        for x in members.split(","):
            if len(x)>0:
                memberUid.append(x)
                full_user = "uid=%s,ou=People,%s" % (x, suffix)
                uniqueMember.append(full_user)
        
        New={"cn":groupName,"gidNumber":gidNumber}
        if memberUid:
            if len(memberUid)>0:
                New["memberUid"] = memberUid
        if len(uniqueMember)>0:
            New['uniqueMember'] = uniqueMember
            
        Current={"cn":res['cn'][0], "gidNumber":res['gidNumber'][0]}
        if res.has_key('memberUid'):
            Current["memberUid"] = copy.copy(res['memberUid'])
        if res.has_key('uniqueMember'):
            Current['uniqueMember'] = copy.copy(res['uniqueMember'])
        if not "groupOfUniqueNames" in res['objectClass']:
            Current['objectClass'] = copy.copy(res['objectClass'])
            New['objectClass'] = copy.copy(res['objectClass'])
            New['objectClass'].append('groupOfUniqueNames')


        print Current
        print New
        DN='cn=%s,ou=Group,%s' % (res['cn'][0],suffix)
        
        if Current == New and not r:
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
        
        return "{success:1,'info':'Group %s updated'}" % (groupName)

    update.exposed = True
    
    
    def get_group(self, groupName=None, gidNumber=None,_dc=None):
        if gidNumber:
            results = do_ldap_search("(&(objectclass=posixGroup)(gidNumber=%s))" % (gidNumber))
        elif groupName:
            results = do_ldap_search("(&(objectclass=posixGroup)(cn=%s))" % (groupName))
        else:
            return "{failure:1,'text':'No group GID or name entered'}"
        if not results:
            return "{failure:1,'text':'No group found'}"

        res=results[0][0][1]
        
        output="{"
        members=''
        for f in groupFields:
            if res.has_key(f) and f is not "memberUid":
                output+="%s:'%s'," % (f, res[f][0])
                
        if res.has_key('memberUid'):
            for m in res['memberUid']:
                members+="%s:" % (m)
        
        output+='members:"%s"' % (members[:-1])
        
        output+="}"
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return output

    get_group.exposed=True
        
    def getMembers(self, groupName=None, gidNumber=None,_dc=None,query=None):
        
        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        if not server or not suffix or not adminUser or not adminPass:
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation: you are not logged in or your session has expired'}"
        
        if gidNumber:
            results = do_ldap_search("(&(objectclass=posixGroup)(gidNumber=%s))" % (gidNumber))
        elif groupName:
            results = do_ldap_search("(&(objectclass=posixGroup)(cn=%s))" % (groupName))
        if not results:
            return "{failure:1,'text':'No members found'}"

        if not results[0][0][1].has_key('memberUid'):
            return "{success:1,'text':'No members found'}"
        members=results[0][0][1]['memberUid']
        
        output="{results: ["
        for member in members:
            user_details = getUser(uidNumber=member)
            if user_details:
                output+="""{cn: '%s',gidNumber:%s,givenName:'%s',sn:'%s',uid:'%s'},""" % (getUserCN(member),member,
                                                                                          user_details['givenName'][0],
                                                                                          user_details['sn'][0],
                                                                                          user_details['uid'][0])
        output+="]}"
        
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return output
    getMembers.exposed=True