var events = require('events');
var ldap = require('ldapjs');

/**
 * Special encoding to UTF16le for ActiveDirectory
 * Not sure why .toString('UTF16le') is no good
 * base64 encoding only appears neccessary if doing batch
 * modifications or from ldapmodify on the shell
 *
 * reference - http://www.cs.bham.ac.uk/~smp/resources/ad-passwds/
 */
function encodePassword(password) {
    var newPassword = '';
    password = '"' + password + '"';
    for (var i = 0; i < password.length; i++) {
        newPassword += password[i] + "\000";
    }
    return new Buffer(newPassword);
}

var adjs = function(url, baseDN, username, password)
{
	var self = this;
	var ldapclient = ldap.createClient({
	    url: url,
	    maxConnections: 10,
	    bindDN: 'CN='+username+',CN=Users,'+baseDN,
	    bindCredentials: password
	});

	ldapclient.bind('CN='+username+',CN=Users,'+baseDN,password,function(err){
        self.emit('bind',err ? { success: false, error: err } : { success: true });
    });

	/**
	 * Create new users in ActiveDirectory
	 * Triggered via commitUser
	 *
	 * @param user - Object
	 * @param callback - Function(success[,data]){}
	 */
	this.createUser = function(user, callback)
	{
	    if (!user.username || !user.firstname || !user.lastname || !user.password) {
	        callback(false);
	        return false; 
	    }

	    var entry = { 
	        cn: user.firstname + ' ' + user.lastname + ' ' + user.username,
	        sn: user.lastname,
	        userAccountControl: 514,
	        accountExpires: 0,
	        givenName: user.firstname,
	        userPrincipalName: user.username + '@domain.local',
	        mail: user.email,
	        sAMAccountName: user.username,
	        homeDirectory: "\\Path\\To\\Home\\" + user.username,
	        homeDrive: 'Z:',
	        objectClass: ["top","person","organizationalPerson","user"]
	    };

	    ldapclient.add('cn='+entry.cn+',cn=Users,'+ldap_base, entry, function(err){
	        if (err) {
	            callback(false);
	            return false;
	        }

	        var password = encodePassword(user.password);
	        var changes = [
	            new ldap.Change({
		            operation: 'replace',
		            modification: {
		                unicodePwd: password
		            }
		        }),
		        new ldap.Change({
		            operation: 'replace',
		            modification: {
		                userAccountControl: 66048 // Enable the account with no password expiration
		            }
		        })
	        ];

	        ldapclient.modify('cn='+entry.cn+',cn=Users,'+ldap_base, changes, function(err){
	            if (err) {
	                callback(false);
	            }
	            else { // Create the user's home directory
	                try {
	                    fs.mkdir(ldap_user_basedir+user.username);
	                } catch(e) {
	                    return callback(false);
	                }
	                callback(true);
	            }
	        });
	    });
	};

	this.resetPassword = function(username, password, callback)
	{
	    if (!username || !password) {
	        callback(false);
	        return false; 
	    }

	    var password = encodePassword(password);
	    var changes = [
	        new ldap.Change({
		        operation: 'replace',
		        modification: {
		            unicodePwd: password
		        }
		    });
	    ];

	    ldapclient.modify('sAMAccountName='+username+',cn=Users,'+ldap_base, changes, function(err){
	       callback(err ? false : true);
	    });
	};

	/**
	 * ldap query to see if a username exists in ActiveDirectory
	 * 
	 * userExists('jdoe',function(success[,data]){ });
	 */
	this.userExists = function(query, opts, callback)
	{
		var username = query;
	    if (!username) {
	        callback(false);
	        return false; 
	    }

	    var opts = { 
	        filter: '(sAMAccountName='+username+')',
	        scope: 'sub',
	        sizeLimit: 1,
	    };
	    
	    ldapclient.search(ldap_base, opts, function(err, res){
	        if (err) {
	            callback(false);
	            return false;
	        }

	        var resEntry = null;

	        res.on('searchEntry', function(entry) {
	            resEntry = entry;
	        });

	        res.on('error', function(err) {
	        });

	        res.on('end', function(result) {

	            if (result.status !== 0) {
	                callback(false);
	                return false;
	            }

	            if (resEntry && resEntry.object.sAMAccountName == username) {
	                callback(true);
	                return true;
	            } else {
	                callback(false);
	                return false;
	            }
	        });
	    });
	};
};

