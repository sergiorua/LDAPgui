import ldap
import ldap.modlist as modlist
import cherrypy
from utils import *
from config import *


def isAccountLocked(username):
    filter="(&(objectclass=posixAccount)(uid=%s))" % (username)
    results = do_ldap_search(filter, ['nsaccountlock'])
    if not results:
        return False
    
    if "nsaccountlock" in results[0][0][1]:
        return results[0][0][1]['nsaccountlock'][0]
    return False

def getMembers(uidNumber, uid=None):
    suffix=cherrypy.session['suffix']
    filter="(|(memberUid=%s)(uniqueMember=uid=%s,ou=people,%s))" % (uidNumber,uid,suffix)
    results = do_ldap_search(filter, ['cn'])
    if not results:
        return None
    
    groups=[]
    for res in results:
        try:
            groups.append(res[0][1]['cn'][0])
        except:
            pass
    
    return groups
    
    
def removeUserGroups(username=None,userdn=None):
    # LDAP Server details
    server = cherrypy.session['server']
    suffix = cherrypy.session['suffix']
    adminUser = cherrypy.session['username']
    adminPass = cherrypy.session['password']
    
    if username and userdn:
        filter = "(&(objectclass=posixGroup)(|(memberUid=%s)(uniqueMember=%s)))" % (username, userdn)
    elif userdn:
        uidNumber = getUserUID(DN=userdn)
        filter = "(&(objectclass=posixGroup)(uniqueMember=%s))" % (userdn)
    elif username:
        filter = "(&(objectclass=posixGroup)(memberUid=%s))" % (username)
    else:
        return """{'failure':'1','info':'uidNumber or DN required'}"""
            
    """ getting group DN from gidNumber """
    results = do_ldap_search(filter)

    l = ldap.open(server)
    try:
        l.simple_bind_s(adminUser, adminPass)
    except ldap.LDAPError, e:
        err = parse_ldap_error(e)
        print (err)
        return False

    for res in results:
        DN=copy.copy(res[0][0])
        res=copy.copy(res[0][1])
 
        if not res: 
            print "++++ Group not found: %s\n" % (filter)
            return False
    
        if len(DN) < 1: continue
        Current={"gidNumber":res['gidNumber'][0]}
    
        members=[]
        uniqueMembers=[]
        
        if 'memberUid' in res:            
            Current["memberUid"] = res['memberUid']
            members = copy.copy(res['memberUid'])
        if 'uniqueMember' in res:
            Current['uniqueMember'] = res['uniqueMember']
            uniqueMembers = copy.copy(res['uniqueMember'])

        
        if username and username in members:
            members.remove(str(username))
        if userdn and userdn in uniqueMembers:
            uniqueMembers.remove(userdn)
    
        New={'gidNumber':res['gidNumber'][0],
             "memberUid":members,
             "uniqueMember":uniqueMembers}
        
    
        if New == Current:
            print ("=> No changes needed to group %s" % (DN))
            continue    
                
        try:
            l.modify_s(DN, modlist.modifyModlist(Current, New))
        except ldap.LDAPError, e:
            print parse_ldap_error(e)
            continue
        
    l.unbind_s()
        
    return True
    

def addUserToGroup(username=None,userdn=None,gid=None,group=None):
    # LDAP Server details
    server = cherrypy.session['server']
    suffix = cherrypy.session['suffix']
    adminUser = cherrypy.session['username']
    adminPass = cherrypy.session['password']
    
    if not group:
        filter = "(&(objectclass=posixGroup)(gidNumber=%s))" % (gid)
    else:
        filter = "(&(objectclass=posixGroup)(cn=%s))" % (group)
            
    """ getting group DN from gidNumber """
    results = do_ldap_search(filter)
    DN=results[0][0][0]
    res = results[0][0][1]
 
    if not res: 
        print "++++ Group not found: %s\n" % (filter)
        return False
    
    if len(DN) < 1: return False
    
    Current={"gidNumber":res['gidNumber'][0]}
    
    
    members=[]
    uniqueMembers=[]
    if 'memberUid' in res:
        Current["memberUid"] = copy.copy(res['memberUid'])
        members = copy.copy(res['memberUid'])
    if r'uniqueMember' in res:
        Current['uniqueMember'] = copy.copy(res['uniqueMember'])
        uniqueMembers = copy.copy(res['uniqueMember'])
        
    # the new member
    if username:
        members.append(str(username))
    if userdn:
        uniqueMembers.append(userdn)
    
    New={'gidNumber':res['gidNumber'][0],
         "memberUid":members,
         "uniqueMember":uniqueMembers}

    if not "groupOfUniqueNames" in res['objectClass']:
        Current['objectClass'] = copy.copy(res['objectClass'])
        New['objectClass'] = copy.copy(res['objectClass'])
        New['objectClass'].append('groupOfUniqueNames')
        
    if New == Current:
        return True
    
    l = ldap.open(server)
    try:
        l.simple_bind_s(adminUser, adminPass)
    except ldap.LDAPError, e:
        print parse_ldap_error(e)
        return False
        
    if Current == New:
        return True
        
    try:
        l.modify_s(DN, modlist.modifyModlist(Current, New))
    except ldap.LDAPError, e:
        print parse_ldap_error(e)
        return False
        
    l.unbind_s()
        
    return True
    

def getUserCN(uid):
    results = do_ldap_search("(&(objectclass=posixAccount)(uidNumber=%s))" % (uid),['cn'])
    if not results:
        return 0

    res=results[0][0][1]['cn'][0]
    return res

def getUserDN(username):
    results = do_ldap_search("(&(objectclass=posixAccount)(uid=%s))" % (username))
    if not results:
        return 0

    res=results[0][0][0]
    return res

def getUserUID(username=None,DN=None):
    if username:
        filter="(&(objectclass=posixAccount)(uid=%s))" % (username)
    elif DN:
        try:
            x=DN.split(",")[0]
        except:
            return False
        filter="(&(objectclass=posixAccount)(%s))" % (x)
    else:
        return False
    
    results = do_ldap_search(filter,['uidNumber'])
    if not results:
        return 0

    res=results[0][0][1]['uidNumber'][0]
    return res


def getUser(uidNumber=None, uid=None):
    if not uidNumber and not uid:
        return None
    if uidNumber:
        results = do_ldap_search("(&(objectclass=posixAccount)(uidNumber=%s))" % (uidNumber))
    elif uid:
        results = do_ldap_search("(&(objectclass=posixAccount)(uid=%s))" % (uid))
    if not results:
        return 0

    res=results[0][0][1]
    return res


class User(object):
    def update(self, server=None,suffix=None,username=None, firstname=None,lastname=None,
            uidNumber=None,gidNumber=None,homedir=None, password=None,password2=None,
            loginShell="/bin/bash",
            email=None,groups=None,krb="off",forceNewPassword="off",_dc=None):

        try:
            server = cherrypy.session['server']
            suffix = cherrypy.session['suffix']
            adminUser = cherrypy.session['username']
            adminPass = cherrypy.session['password']
        except:
            #doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation: you are not logged in or your session has expired'}"
        if not logged_in():
            #doLogout('You cannot be here')
            return "{failure:1,'text':'Access violation: you are not logged in or your session has expired'}"
        
        # All good so far. Creating now Current and New changes list
        results = do_ldap_search('(&(objectclass=posixAccount)(uid=%s))' % (username))
        
        DN=results[0][0][0]
        res=results[0][0][1]

        Current={}
        """
        for f in userFields:
            if res.has_key(f):
                if res[f][0]:
                    Current[f] = str(res[f][0])
        """
        New={}
        if firstname:
            New['givenName'] = firstname
            if 'givenName' in res:
                Current['givenName'] = res['givenName'][0]
            else:
                Current['givenName'] = ''

            if "gecos" in res:
                Current['gecos'] = copy.copy(res['gecos'][0])
            else:
                New['gecos'] = firstname

        if uidNumber:
            if "Leave" in uidNumber:
                uidNumber = autoGen_uid(server, suffix)            
            New['uidNumber'] = str(uidNumber)
            Current['uidNumber'] = res['uidNumber'][0]

        if gidNumber:
            New['gidNumber'] = str(gidNumber)
            Current['gidNumber'] = res['gidNumber'][0]
        if homedir:
            New['homeDirectory'] = homedir
            Current['homeDirectory'] = res['homeDirectory'][0]
        if email:
            New['mail'] = email
            if 'mail' in res:
                Current['mail'] = res['mail'][0]
            else:
                Current['mail']=''
                
        if password:
            New['userPassword'] = password
            Current['userPassword'] = "something"
                
            if krb in "on" "yes":
                change_krb_password(username,password)

        #Current['objectClass'] = res['objectClass']
        if lastname:
            New['sn'] = lastname
            if 'sn' in res:
                Current['sn'] = res['sn'][0]
        
            if not "inetOrgPerson" in res['objectClass']:
                New['objectClass']=['inetOrgPerson']

        if firstname and lastname:
            New['gecos'] = "%s %s" % (firstname, lastname)
        
        if "loginShell" in res:
            Current['loginShell'] = res['loginShell'][0]
            New['loginShell'] = loginShell
        
        if forceNewPassword in "on" "yes":
            shadowLastChange="0"
        else:
            shadowLastChange=str(int(round(time()/24/60/60)))
        New['shadowLastChange'] = shadowLastChange
        if 'shadowLastChange' in res:
            Current['shadowLastChange'] = copy.copy(res['shadowLastChange'][0])
        else:
            Current['shadowLastChange']="0"

        """ If you are editing the account, we assume it should be unlock """
        if isAccountLocked(username):
            Current['nsaccountlock'] = 'true'
            New['nsaccountlock'] = "false"
        
        # before re-adding the groups, remove the current ones
        removeUserGroups(username=username,userdn=DN)
        for x in groups.split(","):
            if len(x)>0:
                addUserToGroup(username=username,userdn=DN,gid=x)
        
        if Current == New:
            return "{success:1,'info':'User %s updated successfully'}" % (username)

        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{failure:1,'info':"%s"}""" % (err)
        
        try:
            l.modify_s(DN, modlist.modifyModlist(Current, New))
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            if not "no changes" in err:
                return """{failure:1,'info':"%s"}""" % (err)
        
        l.unbind_s()
        
        return "{success:1,'info':'User %s updated successfully'}" % (username)
    update.exposed = True
    
    def add(self, server=None,suffix=None,username=None, firstname=None,lastname=None,
            uidNumber=None,gidNumber=None,homedir=None, password=None,password2=None,
            loginShell="/bin/bash",
            email=None,groups=None,krb="off",forceNewPassword="off",_dc=None):

        try:
            server = cherrypy.session['server']
            suffix = cherrypy.session['suffix']
            adminUser = cherrypy.session['username']
            adminPass = cherrypy.session['password']
        except:
            #doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation: you are not logged in or your session has expired'}"
        if not logged_in():
            #doLogout('You cannot be here')
            return "{failure:1,'text':'Access violation: you are not logged in or your session has expired'}"
        
        if not uidNumber or "Leave" in uidNumber:
            uidNumber = autoGen_uid(server, suffix)
        
        if uidNumber < 500:
            return "{'failure':1,'info':'Security violation: Invalid UID number'}"
        
        if not server or not suffix: return "{'failure':1,'info':'Missing server or suffix'}"
        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{'failure':1,'info':"%s"}""" % (err)
    
        if not homedir:
            homedir='/export/home/'+username

        if forceNewPassword in "on" "yes":
            shadowLastChange="0"
        else:
            shadowLastChange=str(int(round(time()/24/60/60)))
        
        attrs = {'uid':username,
                 'givenName':firstname,
                 'cn':username,
                 'sn':lastname,
                 'mail':email,
                 'userPassword':password,
                 'homeDirectory':homedir,
                 'uidNumber':str(uidNumber),
                 'gidNumber':str(gidNumber),
                 'mail':str(email),
                 'loginShell':loginShell,
                 'gecos':"%s %s" % (str(firstname), str(lastname)),
                 'objectclass':['inetOrgPerson','posixAccount','top','shadowAccount','person','organizationalPerson'],
                 'shadowMax': shadowMax,
                 'shadowMin': shadowMin,
                 'shadowWarning':shadowWarning,
                 'shadowLastChange': shadowLastChange,
                 }


        groupsList=[]
        for group in groups.split(","):
             if len(group)>1:
                 groupsList.append(group)
            
        
        id='uid=%s,ou=People,%s' % (username,suffix)
        try:
            l.add_s(id, modlist.addModlist(attrs))
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{'failure':1,'info':"%s"}""" % (err)

        for x in groups.split(","):
            if len(x)>0:
                print "Calling addUserGroup for user %s " % (username)
                addUserToGroup(username=username,userdn=id,gid=x)
        
        if krb in "on" "yes":
            create_krb_user(username,password)

        l.unbind_s()

        return "{'success':1,'info':'User %s added successfully'}" % (username)
    add.exposed=True
    
    def delete(self,server=None,suffix=None, username=None,krb="on"):
        try:
            server = cherrypy.session['server']
            suffix = cherrypy.session['suffix']
            adminUser = cherrypy.session['username']
            adminPass = cherrypy.session['password']
        except:
            #doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation: you are not logged in or your session has expired'}"
        if not logged_in():
            #doLogout('You cannot be here')
            return "{failure:1,'text':'Access violation: you are not logged in or your session has expired'}"
        
        if not username or not server or not suffix: 
            return "{'failure':1,'info':'Missing username'}"
        
        user_details = getUser(uid=username)
        deleteDN = "uid=%s,ou=People,%s" % (username, suffix)
        uidNumber = user_details['uidNumber'][0]
        
        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{'failure':1,'info':"%s"}""" % (err)

        #deleteDN=getUserDN(username)
        if not deleteDN:
            return "{'failure':1,'info':'User not found'}"
        
        try:
            l.delete_s(deleteDN)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{'failure':1,'info':"%s"}""" % (err)

        l.unbind_s()

        if krb in "on" "yes":
            delete_krb_user(username)

        removeUserGroups(username=username, userdn=deleteDN)
        
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return "{success:1,info:'User deleted',uid:'%s'}" % (username)
    
    delete.exposed = True
    
    def list(self, server=None, suffix=None, searchFilter=None,_dc=None,query=None):
        server = cherrypy.session['server']
        suffix = cherrypy.session['suffix']
        adminUser = cherrypy.session['username']
        adminPass = cherrypy.session['password']
        if not server or not suffix or not adminUser or not adminPass or not logged_in():
            doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation: you are not logged in or your session has expired'}"
        
        print "==>> Getting users for %s , %s\n" % (server, suffix) 
        
        if not searchFilter:
            searchFilter='(&(uid=*)(objectclass=posixAccount))'
        retrieveAttributes = None
        
        results = do_ldap_search(searchFilter, retrieveAttributes)

        #return "{'success':'Got %s entries'}" % (len(results))
        output = "{results:["
        for res in results:
            res = res[0][1]
            if not 'mail' in res: 
                res['mail']=[]
                res['mail'].append('')
            if not 'givenName' in res:
                res['givenName']=[]
                res['givenName'].append('')            
            if not 'sn' in res:
                res['sn']=[]
                res['sn'].append('')

            output += """{uid:'%s',firstname:'%s',surname:'%s',uidNumber:'%s',gidNumber:'%s',homedir:'%s',mail:'%s',loginShell:'%s'},""" % (res['uid'][0],res['givenName'][0],res['sn'][0],
                                             res['uidNumber'][0],res['gidNumber'][0],
                                             res['homeDirectory'][0],
                                             res['mail'][0],
                                             res['loginShell'][0])
        output += "]}"
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return output
    list.exposed = True

    def unlock(self, username=None, value='false'):
        return self.lock(username, value)
    unlock.exposed=True
    
    
    def lock(self, username=None, value='true'):
        try:
            server = cherrypy.session['server']
            suffix = cherrypy.session['suffix']
            adminUser = cherrypy.session['username']
            adminPass = cherrypy.session['password']
        except:
            #doLogout('You cannot be here')
            return "{failure:1,'info':'Access violation: you are not logged in or your session has expired'}"
        if not logged_in():
            #doLogout('You cannot be here')
            return "{failure:1,'text':'Access violation: you are not logged in or your session has expired'}"
        
        # All good so far. Creating now Current and New changes list
        results = do_ldap_search('(&(objectclass=posixAccount)(uid=%s))' % (username),['nsaccountlock','loginShell'])
        
        DN=results[0][0][0]
        res=results[0][0][1]

        Current={}
        New={}
        if "loginShell" in res:
            Current['loginShell'] = res['loginShell'][0]
            if "/bin/false" == res['loginShell'][0]:
                New['loginShell'] = "/bin/bash"
            else:
                New['loginShell'] = "/bin/false"

        if "nsaccountlock" in res:
            Current['nsaccountlock'] = res['nsaccountlock'][0]
            if "true" in res['nsaccountlock'][0]:
                value = 'false'
            else:
                value = 'true'
                
        New['nsaccountlock']=str(value)

        l = ldap.open(server)
        try:
            l.simple_bind_s(adminUser, adminPass)
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{'failure':1,'info':"%s"}""" % (err)
        
        try:
            l.modify_s(DN, modlist.modifyModlist(Current, New))
        except ldap.LDAPError, e:
            err = parse_ldap_error(e)
            return """{'failure':1,'info':"%s"}""" % (err)
        
        l.unbind_s()        
        
        cherrypy.response.headers['Content-Type'] = "text/plain"
        if value == 'true':
            return "{success:1,info:'User %s locked',uid:'%s',value:'%s'}" % (username,username,value)
        else:
            return "{success:1,info:'User %s unlocked',uid:'%s',value:'%s'}" % (username,username,value)
    lock.exposed=True
    
    """ I'm assuming UID is unique!! """
    def get_user(self, userid=None, _dc=None):
        retAttrs=['version','mail','loginShell','shadowMin','uid','userPassword',
                  'shadowWarning','uidNumber','shadowMax','gidNumber','gecos',
                  'sn','homeDirectory','givenName','shadowLastChange','cn',
                  'nsaccountlock']

        results = do_ldap_search('(&(objectclass=posixAccount)(uid=%s))' % (userid),retAttrs)
        if not results:
            return "{}"
        res=results[0][0][1]
        
        output="{"
        for f in retAttrs:
            if f in res:
                output+="%s:'%s'," % (f, res[f][0])
        
        groups = getMembers(res['uidNumber'][0],res['uid'][0])
        if groups:
            groups_list=':'.join(groups)
            output+="groups:'%s'" % (groups_list)
            
        output+="}"
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return output
        
    get_user.exposed=True
