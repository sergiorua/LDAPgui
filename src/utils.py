from config import *
import cherrypy
import ldap
import sys
import os
import urlparse
import copy
from time import time


def do_ldap_connect():
    server = cherrypy.session['server']
    suffix = cherrypy.session['suffix']
    adminUser = cherrypy.session['username']
    adminPass = cherrypy.session['password']
    if not server or not suffix or not adminUser or not adminPass:
        doLogout('You cannot be here')
        return "{failure:1,'text':'Access violation'}"
    
    l = ldap.open(server)
    try:
        l.simple_bind_s(adminUser, adminPass)
    except ldap.LDAPError, e:
        err = parse_ldap_error(e)
        return "{'failure':1,'info':'%s'}" % (e)
    return l
    
def do_ldap_search(searchFilter=None, retrieveAttributes=None):
    if not searchFilter:
        return []

    server = cherrypy.session['server']
    suffix = cherrypy.session['suffix']
    adminUser = cherrypy.session['username']
    adminPass = cherrypy.session['password']

    if not server or not suffix or not adminUser or not adminPass:
        doLogout('You cannot be here')
        return []
        
    l = ldap.open(server)
    try:
        # l.simple_bind_s(adminUser, adminPass)
        l.simple_bind_s()
    except ldap.LDAPError, e:
        return []

    baseDN=suffix
    searchScope = ldap.SCOPE_SUBTREE
    
    # print "\tDEBUG: %s, %s, %s" % (baseDN, searchScope,searchFilter) 
    try:
        res_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
    except ldap.LDAPError, e:
        return []

    results=[]
    while 1:
        try:
            result_type, result_data = l.result(res_id, 0)
        except ldap.LDAPError, e:
            l.unbind_s()
            return []
        if result_data == []: break
        if result_type == ldap.RES_SEARCH_ENTRY:
            results.append(result_data)
    
    return results

def autoGen_gid():
    results = do_ldap_search('(objectClass=posixGroup)', ['gidNumber'])
    
    maxGID=100
    for res in results:
        x = int(res[0][1]['gidNumber'][0])
        if x > maxGID: maxGID=x

    return maxGID+1

        
def autoGen_uid(server=None, suffix=None, searchFilter=None):
       # for test only
    if not server: server="10.128.50.19"
    if not suffix: suffix='dc=ufi,dc=co,dc=uk'
        
    # return value
    maxUID = 0

    l = ldap.open(server)
    try:
        l.simple_bind_s()
    except ldap.LDAPError, e:
        err = parse_ldap_error(e)
        return "{'failure':1,'info':'%s'}" % (err)

    baseDN=suffix
    searchScope = ldap.SCOPE_SUBTREE
    if not searchFilter:
        searchFilter='(&(uid=*)(objectclass=posixAccount))'
    retrieveAttributes = ['uidNumber']
        
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
            try:
                x = int(result_data[0][1]['uidNumber'][0])
            except:
                continue
            if x > maxUID: maxUID=x

    return maxUID+1


##################### session ###################################
def session_expired():
    try:
        start_time = int(cherrypy.session.get('time'))
    except:
        return True
    
    if int(time()) > start_time:
        """ Session expired """
        return True
    return False

def logged_in(max_session_time=600):
    try:
        server = cherrypy.session.get('server')
    except:
        return False

    try:
        username = cherrypy.session.get('username')
    except:
        return False
    
    if session_expired():
        return False
    
    if username is None or server is None:
        return False
    if len(username) < 3 or len(server) < 3:
        return False
    
    cherrypy.session['time'] = round(time())+max_session_time
    return True

def init_session(data, max_session_time=600):
    cherrypy.session['server'] = data['server']
    cherrypy.session['port'] = data['port']
    cherrypy.session['username'] = data['username']
    cherrypy.session['password'] = data['password']
    cherrypy.session['suffix'] = data['suffix']
    cherrypy.session['time'] = round(time())+max_session_time
    cherrypy.session['ssl'] = data['ssl']
    
def destroy_session():
    for k in 'server','username','password','suffix':
        if cherrypy.session.has_key(k):
            del cherrypy.session[k]

def doLogout(msg=''):
    destroy_session();
    #raise cherrypy.HTTPRedirect('/login?msg=%s' % (msg))
    raise do_redirect('/login?msg=%s' % (msg))


def do_redirect(destination, ssl=True):
        #err_msg = getCookie('error')
        if "https:" in destination or "http" in destination:
                raise cherrypy.HTTPRedirect(destination)
        if ssl:
                url = urlparse.urlparse(cherrypy.url())
                secure_url = urlparse.urlunsplit(('https', url[1], destination,
                        '', ''))
                raise cherrypy.HTTPRedirect(secure_url)
        else:
                raise cherrypy.HTTPRedirect(destination)


#######################################################################################

def js_timeout(timeout=5000):
    output = msg
    output+="<SCRIPT TYPE='text/javascript'>"
    output+="setTimeout('',%s);"
    output+="</SCRIPT>"
    
    return output % (timeout)

def js_back(msg='',timeout=5000):
    output = msg
    output+="<SCRIPT TYPE='text/javascript'>"
    output+="setTimeout('history.go(-1)',%s);"
    output+="</SCRIPT>"
    
    return output % (timeout)


def is_defined(var):
    try:
        var
    except:
        var = None
    
    return var

def setCookie(name, value):
    cherrypy.response.cookie[name] = value
    cherrypy.response.cookie[name]['path'] = '/'
    #cherrypy.response.cookie[name]['max-age'] = 3600
    cherrypy.response.cookie[name]['version'] = 1

def delCookie(name):
    if cherrypy.request.cookie.has_key(name):
        cherrypy.response.cookie[name] = cherrypy.request.cookie[name].value
        cherrypy.response.cookie[name]['expires'] = 0

def getCookie(name):
    cookies = cherrypy.request.cookie
    if name in cookies:
        return cookies[name].value
    else:
        return None

def make_secure(header="Secure"):
        secure = cherrypy.request.headers.get(header, False)
        if not secure:
                url = urlparse.urlparse(cherrypy.url())
                secure_url = urlparse.urlunsplit(('https', url[1], url[2],
                        url[3], url[4]))
                raise cherrypy.HTTPRedirect(secure_url)

cherrypy.tools.secure = cherrypy.Tool('before_handler', make_secure)

def parse_ldap_error(e, showInfo=True):
    if type(e) == ldap.NO_SUCH_OBJECT:
        e = e.message

    if type(e) == list or type(e) == ldap.INSUFFICIENT_ACCESS:
        e = e[0]
    else:
        try:
            e = e[0]
        except:
            pass
    msg = "Unknown LDAP error"
    if type(e) == dict:
        if e.has_key('desc'):
            msg = e['desc']
        if e.has_key('info') and showInfo:
            msg = "<b>%s</b><br>%s" % (msg,e['info'])
    elif type(e) == str:
        msg = e
    
    # WARNING: character return makes javascript to fail
    msg = msg.replace('\n', '').replace('\r', '')
    return msg


""" KERBEROS """
pyKadm=True
pExpect=True
try:
    import _pykadm5
except:
    pyKadm=False

try:
    import pexpect
except:
    pExpect = False

if pyKadm and useKrb5:
    def ssh_connect(host=None,username=None, password=None):
        pass
    def create_krb_user(username,password,k=None):
        handle = _pykadm5.init_with_password(kerberosServer['adminUser'],kerberosServer['adminPass'],None,None)
        
        t = username + '@' + kerberosServer['realm']
        if not t in _pykadm5.get_principals(handle):
            return _pykadm5.create_principal(handle,username,password,{})
        else:
            return 1

        
    def delete_krb_user(username,k=None):
        handle = _pykadm5.init_with_password(kerberosServer['adminUser'],kerberosServer['adminPass'],None,None)
        return _pykadm5.delete_principal(handle,username)
        
    def change_krb_password(username,password):
        handle = _pykadm5.init_with_password(kerberosServer['adminUser'],kerberosServer['adminPass'],None,None)
        return _pykadm5.change_password(handle,username,password)
       
elif not "win" in sys.platform and os.path.exists(kerberosServer['kadmin']) and pExpect and useKrb5:
    def ssh_connect(host=None,username=None, password=None):
        COMMAND_PROMPT = '[$#] '
        TERMINAL_PROMPT = r'Terminal type\?'
        TERMINAL_TYPE = 'vt100'
        SSH_NEWKEY = r'Are you sure you want to continue connecting \(yes/no\)\?'
        
        if not host: username=kerberosServer['krbhost']
        if not username: username=kerberosServer['sshuser']
        if not password: username=kerberosServer['sshpass']
        
        s = pexpect.spawn('%s %s@%s' % (kerberosServer['ssh'],username,host))
        i = s.expect([pexpect.TIMEOUT, SSH_NEWKEY, '[Pp]assword: '])
        if i == 0:
            return None
        if i == 1:
            s.sendline ('yes')
            s.expect('[Pp]assword: ')
        
        s.sendline(password)
        i = s.expect (['Permission denied', '[pP]assword: ',TERMINAL_PROMPT, COMMAND_PROMPT])
        if i == 0 or i == 1:
            return None
        if i == 2:
            s.sendline (TERMINAL_TYPE)
            s.expect (COMMAND_PROMPT)
        return s    
    
    def create_krb_user(username,password,k=None):
        if not k:
                k = pexpect.spawn('%s -p %s' % (kerberosServer['kadmin'],kerberosServer['adminUser']))
        else:
                k.sendline('%s -p %s' % (kerberosServer['kadmin'],kerberosServer['adminUser']))
        k.expect('Password for.*: ')
        k.sendline(kerberosServer['adminPass'])

        i = k.expect(['kadmin: Incorrect.*','kadmin: '])
        if i == 0:
                return "{failure:1,'info':'kadmin: permission denied'}"
                
        k.sendline('addprinc %s' % (username))
        k.expect('Enter password for principal.*: ')
        k.sendline(password)
        k.expect('Re-enter password for principal.*: ')
        k.sendline(password)
        k.expect('kadmin: ')
        k.sendline('exit')

        k.close()
        return "{success:1,'info':'kadmin: principal created'}"
    
    def delete_krb_user(username,k=None):
        if not k:
                k = pexpect.spawn('%s -p %s' % (kerberosServer['kadmin'],kerberosServer['adminUser']))
        else:
                k.sendline('%s -p %s' % (kerberosServer['kadmin'],kerberosServer['adminUser']))
        k.expect('Password for.*: ')
        k.sendline(kerberosServer['adminPass'])

        i = k.expect(['kadmin: Incorrect.*','kadmin: '])
        if i == 0:
                return "{failure:1,'info':'kadmin: permission denied'}"
                
        k.sendline('delprinc %s' % (username))
        k.expect('Are you sure.*')
        k.sendline('yes')
        k.expect('kadmin: ')
        k.sendline('exit')

        k.close()
        return "{success:1,'info':'kadmin: principal deleted'}"
    
    def change_krb_password(username,password):
        if not k:
                k = pexpect.spawn('%s -p %s' % (kerberosServer['kadmin'],kerberosServer['adminUser']))
        else:
                k.sendline('%s -p %s' % (kerberosServer['kadmin'],kerberosServer['adminUser']))
        k.expect('Password for.*: ')
        k.sendline(kerberosServer['adminPass'])

        i = k.expect(['kadmin: Incorrect.*','kadmin: '])
        if i == 0:
                return "{failure:1,'info':'kadmin: permission denied'}"
                
        k.sendline('cpw %s' % (username))
        k.expect('Enter password for principal.*: ')
        k.sendline(password)
        k.expect('Re-enter password for principal.*: ')
        k.sendline(password)
        k.expect('kadmin: ')
        k.sendline('exit')

        k.close()
        return "{success:1,'info':'kadmin: password changed'}"
        
else:
    def create_krb_user(*args, **kwargs):
        pass
    def delete_krb_user(*args, **kwargs):
        pass
    def change_krb_password(username,password):
        pass
    def ssh_connect(*args, **kwargs):
        pass
