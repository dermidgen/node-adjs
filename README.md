#Active Directory Utilities for Node

adjs is an utility client for Microsoft Active Directory based on ldapjs.  The goal of this library
is to support finding, creating, updating and authenticating users in Active Directory.  Existing node libraries
do pretty well at authenticating and finding users, but do not address creating or updating users.

##Installation
npm install adjs

##Usage
```js
var adclient = require('adjs')('ldaps://ad-host:636','dc=domain,dc=com', 'binduser@domain.com','bindpassword');
adclient.createUser({}, function(err){});
```