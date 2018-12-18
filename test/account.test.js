const mongoose = require('mongoose');
const Account = require('../lib/account');
const sha256 = require('sha256');
const assert = require('assert');
const _ = require('lodash');

const schema = new mongoose.Schema({
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
    name: {type: String},
    mobile: {type: String}
});

describe('account-password', () => {
    let account, token, userId, User;
    before(async () => {
        mongoose.connect('mongodb://127.0.0.1:27017/test', {useNewUrlParser: true});
        User = mongoose.model('User', schema);
        await User.deleteMany({username: /test/});
        account = new Account(User, {loginExpirationInDays: 30});
    });

    describe('public methods: ', () => {
        it('`createUser()` should return new user object', async () => {
            let user = {
                username: 'test',
                password: {
                    algorithm: 'sha-256',
                    digest: sha256('123456')
                },
                name: 'test'
            };
            let res = await account.createUser(user);
            res = res.toObject();
            assert.ok(res.hasOwnProperty('_id'));
            assert.ok(res.hasOwnProperty('services'));
            assert.ok(res.hasOwnProperty('createdAt'));
            assert.equal(res.username, user.username);
            assert.equal(res.services.resume.loginTokens.length, 0);
            // console.log('user id: ', res._id);
        });

        it('`loginWithPassword()` should return login token and tokenExpires', async () => {
            let data = {
                username: 'test',
                password: {
                    algorithm: 'sha-256',
                    digest: sha256('123456')
                }
            };
            let res = await account.loginWithPassword(data);
            assert.ok(res.hasOwnProperty('id'));
            assert.ok(res.hasOwnProperty('token'));
            assert.ok(res.hasOwnProperty('tokenExpires'));
            assert.ok(_.isDate(res.tokenExpires));
            token = res.token;
            userId = res.id;
            // console.log('login token: ', token);

        });

        it('`loginWithToken()` check whether the token is expired', async () => {
            let res = await account.loginWithToken({resume: token});
            assert.ok(res.hasOwnProperty('userId'));
            assert.ok(res.hasOwnProperty('token'));
            assert.ok(res.hasOwnProperty('tokenExpires'));
        });


        it('`changePassword()` change user password, use new password should login success', async () => {
            let oldPassword = {
                algorithm: 'sha-256',
                digest: sha256('123456')
            };

            let newPassword = {
                algorithm: 'sha-256',
                digest: sha256('abcdef')
            };

            let res = await account.changePassword(userId, oldPassword, newPassword);
            assert.ok(res.hasOwnProperty('userId'));
            assert.equal(res.userId, userId);


            // use old password
            let old = {
                username: 'test',
                password: oldPassword
            };
            try {
                await account.loginWithPassword(old);
            } catch (e) {
                assert.equal(e.message, 'Incorrect password');
            }

            //use new password
            let newpwd = {
                username: 'test',
                password: newPassword
            };

            let newLogin = await account.loginWithPassword(newpwd);
            assert.ok(newLogin.hasOwnProperty('id'));
            assert.ok(newLogin.hasOwnProperty('token'));
            assert.ok(newLogin.hasOwnProperty('tokenExpires'));
            token = newLogin.token;
            // console.log('new password: abcdef');
            // console.log(`new token: ${token}`)
        });

        it('`checkPassword()` check user password', async () => {
            let user = await User.findById(userId);
            user = user.toObject();

            let pwd = {
                algorithm: 'sha-256',
                digest: sha256('abcdef')
            };

            //Use the correct password
            let res = await account.checkPassword(user, pwd);
            assert.ok(res.hasOwnProperty('userId'));
            assert.equal(res.userId, userId);

            //Use the error password
            pwd = {
                algorithm: 'sha-256',
                digest: sha256('123456')
            };
            res = await account.checkPassword(user, pwd);
            assert.ok(res.hasOwnProperty('error'));
            assert.equal(res.error, 'Incorrect password');
        });

        it('`resetPassword()` reset user password, must be logged in', async () => {

            //use error token
            let newPassword = {
                algorithm: 'sha-256',
                digest: sha256('p@ssw0rd')
            };

            try {
                await account.resetPassword('5lA1EXzWsdo85DYpHFxoeJUxZnO6Vn1khOJZ3IPtyEK', newPassword);
            } catch (e) {
                assert.equal(e.message, 'Token expired.')
            }

            //user logged token
            let res = await account.resetPassword(token, newPassword);
            assert.ok(res.hasOwnProperty('userId'));
            assert.equal(res.userId, userId);
            let user = await User.findById(userId);
            user = user.toObject();
            assert.equal(user.services.resume.loginTokens.length, 0);
            // console.log('new password: p@ssw0rd')

        });

        it('`setPassword()` set user password, in the case of non-password registration', async () => {

            //create none password user
            let user = {
                username: 'test2',
                name: 'test2',
                mobile: '123456789'
            };
            let res = await account.createUser(user);
            res = res.toObject();
            assert.ok(!res.services.hasOwnProperty('password'));
            assert.ok(res.hasOwnProperty('_id'));
            assert.ok(res.hasOwnProperty('services'));
            assert.ok(res.hasOwnProperty('createdAt'));
            assert.equal(res.username, user.username);
            assert.equal(res.services.resume.loginTokens.length, 0);

            let newPassword = {
                algorithm: 'sha-256',
                digest: sha256('test2')
            };

            let newres = await account.setPassword(res._id, newPassword);
            assert.equal(newres.userId, res._id);
            let data = await User.findById(newres.userId);
            data = data.toObject();
            assert.ok(data.services.hasOwnProperty('password'));
        })
    });


    describe('private methods: ', () => {
        it('`_getPasswordString()` get use sha256 signature password string', () => {
            let password = sha256('123456abc');
            let password2 = account._getPasswordString('123456abc');
            assert.equal(password, password2);

            //Only 'sha-256' is allowed
            password = {
                algorithm: 'sha-512',
                digest: sha256('123456abc')
            };
            try {
                account._getPasswordString(password);
            } catch (e) {
                assert.equal(e.message, 'Invalid password hash algorithm. Only \'sha-256\' is allowed.')
            }
        })
    })

});
