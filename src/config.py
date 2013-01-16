userFields=['uid','cn','givenName','sn','mail','homeDirectory','uidNumber','gidNumber',
            'userPassword']

groupFields=['gidNumber','cn','memberUid','uniqueMember']

# default password expiring settings
shadowMax="90"
shadowMin= "60"
shadowWarning="7"


#
# LDAP server configuration
#
defaultAdminUser = "cn=Directory Manager"
defaultAdminPass = ""
defaultLDAPServer = "my.ldap.server"
defaultLDAPsuffix = "dc=1to1consultant,dc=co,dc=uk"
dsconf="/opt/SUNWdsee/ds6/bin/dsconf"
dsadm="/opt/SUNWdsee/ds6/bin/dsadm"

# kerberos

useKrb5=False
kerberosServer = {'ssh':'/usr/bin/ssh',
            'krbhost':'KERBEROS_SERVER-IP',
            'sshuser':'LOGIN_USER',
            'sshpass':'LOGIN_PASS',
            'adminUser':'kws/admin',
            'adminPass':'KRB_PASSWORD',
            'kadmin':'/usr/sbin/kadmin',
            'realm':'KRB5.1TO1CONSULTANT.CO.UK'}

