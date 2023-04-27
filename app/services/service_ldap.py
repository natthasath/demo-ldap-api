from decouple import config
from fastapi.responses import JSONResponse
from ldap3 import ALL, SUBTREE, Server, Connection, Tls, SAFE_SYNC, ALL_ATTRIBUTES, MODIFY_REPLACE, MODIFY_ADD
from ldap3.extend.microsoft.modifyPassword import ad_modify_password
import json

class LdapService:
    def __init__(self):
        self.ldap_attr = ['cn', 'givenName', 'sn', 'displayName', 'useraccountcontrol', 'telephonenumber', 'title', 'department', 'userPrincipalName', 'distinguishedName', 'optionalEmail', 'lastLogon', 'whenChanged', 'whenCreated']
        self.ldap_host = None
        self.ldap_port = None
        self.ldap_ssl = None
        self.ldap_user = None
        self.ldap_pass = None
        self.ldap_dn = None

    def config(self, ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn):
        content = {"message": True}
        response = JSONResponse(content=content)
        response.set_cookie(key='ldap_host', value=ldap_host)
        response.set_cookie(key='ldap_port', value=ldap_port)
        response.set_cookie(key='ldap_ssl', value=ldap_ssl)
        response.set_cookie(key='ldap_user', value=ldap_user)
        response.set_cookie(key='ldap_pass', value=ldap_pass)
        response.set_cookie(key='ldap_dn', value=ldap_dn)
        return response

    def get_status(self, status):
        data = {
            512: "Enabled",
            514: "Disabled",
            66048: "Enabled, password never expires",
            66050: "Disabled, password never expires"
        }
        return data[status]
    
    def ad_connect(self, ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass):
        server = Server(ldap_host, port = int(ldap_port), use_ssl = eval(ldap_ssl))
        conn = Connection(server, ldap_user, ldap_pass, auto_bind = True)
        return conn

    def bind_connect(self, ldap_host, ldap_port, ldap_ssl, username, password):
        try:
            server = Server(ldap_host, port = int(ldap_port), use_ssl = eval(ldap_ssl))
            conn = Connection(server, username, password, auto_bind = True)
            return conn
        except:
            return JSONResponse(status_code=403, content={"message": "Invalid username or password"})
    
    def auth(self, ldap_host, ldap_port, ldap_ssl, username, password):
        conn = self.bind_connect(ldap_host, ldap_port, ldap_ssl, username, password)
        if 'JSONResponse' in str(type(conn)):
            return conn
        else:
            return JSONResponse(status_code=200, content={"message": True})
        
    def status_user(self):
        data = {
            512: "Enabled",
            514: "Disabled",
            66048: "Enabled, password never expires",
            66050: "Disabled, password never expires"
        }
        return data
        
    def all_ous(self, ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, ou_name):
        conn = self.ad_connect(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass)
        dn = f'OU={ou_name},{ldap_dn}'
        object = '(objectclass=OrganizationalUnit)'
        conn.search(dn, object)
        return conn.response
    
    def all_groups(self, ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, ou_name):
        conn = self.ad_connect(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass)
        dn = f'OU={ou_name},{ldap_dn}'
        object = '(objectclass=group)'
        conn.search(dn, object)
        return conn.response

    def all_users(self, ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, ou_name):
        conn = self.ad_connect(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass)
        dn = f'OU={ou_name},{ldap_dn}'
        object = '(objectclass=person)'
        conn.search(dn, object, attributes = self.ldap_attr, paged_size=100)
        data = []
        for x in conn.response:
            data.append(x['attributes'])
        return data

    def ou_users(self, ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, dn):
        conn = self.ad_connect(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass)
        object = '(objectclass=person)'
        conn.search(dn, object, attributes = self.ldap_attr)
        data = []
        for x in conn.response:
            data.append(x['attributes'])
        return data

    def search_user(self, ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, username):
        conn = self.ad_connect(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass)
        object = '(&(userPrincipalName=' + username + ')(objectClass=person))'
        try:
            conn.search(ldap_dn, object, attributes = self.ldap_attr)
            return conn.response[0]['attributes']
        except:
            return JSONResponse(status_code=404, content={"message": "Resource not found"})

    def memberof_user(self, ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, username):
        conn = self.ad_connect(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass)
        object = '(&(userPrincipalName=' + username + ')(objectClass=person))'
        try:
            conn.search(ldap_dn, object, attributes = ['memberOf'])
            return conn.response[0]['attributes']['memberOf']
        except:
            return JSONResponse(status_code=404, content={"message": "Resource not found"})

    def forget_password(self, ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, username, national_id):
        conn = self.ad_connect(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass)
        filter = '(&(userPrincipalName=' + username + ')(objectClass=person))'
        try:
            conn.search(ldap_dn, search_filter = filter, attributes = ['*'])
            entry = conn.entries
            data = json.loads(entry[0].entry_to_json())
            if int(data['attributes']['extensionAttribute7'][0]) == national_id:
                optional = data['attributes']['optionalEmail'][0]
                return optional
            else:
                return JSONResponse(status_code=403, content={"message": "Invalid national id"})
        except:
            return JSONResponse(status_code=403, content={"message": "Invalid username"})

    def reset_password(self, ldap_host, ldap_port, ldap_ssl, ldap_dn, username, old_password, new_password):
        conn = self.bind_connect(ldap_host, ldap_port, ldap_ssl, username, old_password)
        if 'JSONResponse' in str(type(conn)):
            return conn
        else:
            object = '(&(userPrincipalName=' + username + ')(objectClass=person))'
            try:
                conn.start_tls()
                conn.search(ldap_dn, object, attributes = self.ldap_attr)
                self.ldap_user_dn = conn.response[0]['attributes']['distinguishedName']
                res = ad_modify_password(conn, self.ldap_user_dn, new_password, old_password, controls = None)
                if res == True:
                    return JSONResponse(status_code=200, content={"message": True})
                else:
                    return JSONResponse(status_code=403, content={"message": "Invalid format new password"})
            except:
                return JSONResponse(status_code=404, content={"message": "Resource not found"})

    def change_optional(self, username, password, optional):
        conn = self.bind_connect(username, password)
        if 'JSONResponse' in str(type(conn)):
            return conn
        else:
            dn = self.get_dn(username.split('@')[1])
            object = '(&(userPrincipalName=' + username + ')(objectClass=person))'
            print(conn.start_tls())
            return True