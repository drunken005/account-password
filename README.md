# account-password
A login service that enables secure password-based login. `current version only support mongodb database`

## Install

```bash
npm install account-password --save
```
## Test
```bash
npm i
npm test
```

## Defining your account schema

e.g:

```bash
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const UserSchema = new Schema({
    _id: {type: String},
    createdAt: {type: Date},
    services: {
        password: {bcrypt: {type: String}},
        resume: {
            loginTokens: {
                type: [
                    {
                        when: Date,
                        hashedToken: String
                    }
                ]
            }
        }
    },
    username: {type: String},
    email: {type: String},
    ....
});
const User = mongoose.model('User', UserSchema);
```
Account data struct
```bash
{
    "_id" : "8xmjaqweQ6vzGg1q3gvt",
    "services" : {
        "password" : {
            "bcrypt" : "$2b$10$JYUDDA4/fhOl6AIT2YFkA.qmL2d1aNQgQz95y35o01FCG6delTQI."
        },
        "resume" : {
            "loginTokens" : [
                {
                    "when" : ISODate("2018-10-29T16:16:36.017+08:00"),
                    "hashedToken" : "3uMs8gNz3b8WfDPnauUxr7migtIc2uwdipAYZefYXcE="
                },
                {
                    "when" : ISODate("2018-10-29T17:12:44.180+08:00"),
                    "hashedToken" : "IRHsJYnna4E123jhY5YqANbkHQ2RqKD9xyv6WDF8xk8="
                }
            ]
        }
    },
    "createdAt" : ISODate("2018-10-29T15:57:34.983+08:00"),
    "username" : "test",
    "__v" : 0
}
```



```bash
const Account = require('account-password');
const options = {
    loginExpirationInDays: 30 //how long (in days) until a login token expires, default 90
}
const account = new Account(User, options);
```

## API

The parameter `password` supports plaintext password and sha256 signaturem, recommend to use sha256 signature
e.g
```bash
const sha256 = require('sha256');

//plaintext password
password = '123456';

//sha256 signaturem
password = {
    algorithm: 'sha-256',
    digest: sha256('123456')
}
```

* #### `createUser(options)` Register a user by username or email or otherwise

  ##### Inputs options
   * `username` require.
   * `email` optional.
   * `password` optional. plaintext password or sha256 signature, `optional` is for compatibility with other registration, such mobile verification code or third parties
   
  ##### Return value
  Promise, registered user info



* #### `loginWithPassword(options)` Login with username or email
  
  ##### Inputs options
   * `username` optional.
   * `email` optional.
   * `password` require. plaintext password or sha256 signature
  
  ##### Return value
  ```bash
    {
        "id": "8xmjaqweQ6vzGg1q3gvt", //user id
        "token": "UAqyxZCfYNde9Bc6EXo-QRVJN9IxgsaaDHF57NkEqr0", //token
        "tokenExpires": "2018-11-15 10:52:02.191", //token expires time
    }
  ```

* #### `loginWithToken(options)` Used to check whether the token is expired
  
  ##### Inputs options
   * `resume` require. Token returned by login
  
  ##### Return value
  ```bash
    {
        "id": "8xmjaqweQ6vzGg1q3gvt", //user id
        "token": "UAqyxZCfYNde9Bc6EXo-QRVJN9IxgsaaDHF57NkEqr0", //token
        "tokenExpires": "2018-11-15 10:52:02.191", //token expires time
    }
  ```

* #### `changePassword(userId, oldPassword, newPassword)` Change user password
  
  ##### Inputs options
   * `userId` require. user id
   * `oldPassword` require. plaintext password or sha256 signature
   * `newPassword` require. plaintext password or sha256 signature
  
  ##### Return value
  Object. {userId: 'xxx'}


* #### `checkPassword(user, password)` Check user password
  
  ##### Inputs options
   * `user` require. Must contain 'services.password.bcrypt' field
   * `password` require. plaintext password or sha256 signature
  
  ##### Return value
  Object.If the password match return {userId: 'xxx'}, otherwise return {error: 'Incorrect password'}


* #### `resetPassword(token, newPlaintextPassword)` Reset user password
  
  ##### Inputs options
   * `token` require. login token
   * `newPlaintextPassword` require. plaintext password or sha256 signature
  
  ##### Return value
  Object. {userId: 'xxx'}


* #### `setPassword(userId, newPlaintextPassword)` Set user password
  
  ##### Inputs options
   * `userId` require. user id
   * `newPlaintextPassword` require. plaintext password or sha256 signature
  
  ##### Return value
  Object. {userId: 'xxx'}

## Other ways login
Post verification call `Account._generateLoginToken({userId:'xxxxxx'})`
