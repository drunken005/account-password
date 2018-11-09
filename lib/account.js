const check = require('./check');
const sha256 = require('sha256');
const bcrypt = require('bcrypt');
const random = require('randomstring');
const createHash = require('create-hash');
const _ = require('lodash');

const BASE64_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
// A large number of expiration days (approximately 100 years worth) that is
// used when creating unexpiring tokens.
const LOGIN_UNEXPIRING_TOKEN_DAYS = 365 * 100;
// how long (in days) until a login token expires
const DEFAULT_LOGIN_EXPIRATION_DAYS = 15;
// how often (in milliseconds) we check for expired tokens
const EXPIRE_TOKENS_INTERVAL_MS = 6 * 1000; // 10 minutes

const VALID_KEYS = ["loginExpirationInDays", "bcryptRounds"];


const setExpireTokensInterval = accounts => {
    setInterval(accounts._expireTokens, EXPIRE_TOKENS_INTERVAL_MS, accounts);
};

class Account {
    constructor(accountModel, options = {}) {
        Object.keys(options).forEach(key => {
            if (!VALID_KEYS.includes(key)) {
                throw new Error(`Accounts.config: Invalid key: ${key}`);
            }
        });
        this.account = accountModel;
        this._options = _.assign({bcryptRounds: 10}, options);
        // setExpireTokensInterval(this);
    }


    _expireTokens(self, oldestValidDate, userId) {
        const tokenLifetimeMs = self._getTokenLifetimeMs();

        // when calling from a test with extra arguments, you must specify both!
        if ((oldestValidDate && !userId) || (!oldestValidDate && userId)) {
            throw new Error("Bad test. Must specify both oldestValidDate and userId.");
        }

        oldestValidDate = oldestValidDate ||
            (new Date(new Date() - tokenLifetimeMs));
        const userFilter = userId ? {_id: userId} : {};


        // Backwards compatible with older versions of meteor that stored login token
        // timestamps as numbers.
        self.account.updateMany({
            ...userFilter,
            $or: [
                {"services.resume.loginTokens.when": {$lt: oldestValidDate}},
                {"services.resume.loginTokens.when": {$lt: +oldestValidDate}}
            ]
        }, {
            $pull: {
                "services.resume.loginTokens": {
                    $or: [
                        {when: {$lt: oldestValidDate}},
                        {when: {$lt: +oldestValidDate}}
                    ]
                }
            }
        }, function (err, res) {
            console.log(new Date(), ' =====================================clear expire tokens ', res);
        });
        // The observe on Meteor.users will take care of closing connections for
        // expired tokens.
    };

    _getPasswordString(password) {
        if (typeof password === "string") {
            password = sha256(password);
        } else { // 'password' is an object
            if (password.algorithm !== "sha-256") {
                throw new Error("Invalid password hash algorithm. " +
                    "Only 'sha-256' is allowed.");
            }
            password = password.digest;
        }
        return password;
    }

    _hashPassword(password, bcryptRounds) {
        bcryptRounds = bcryptRounds || this._options.bcryptRounds;
        password = this._getPasswordString(password);
        return bcrypt.hashSync(password, bcryptRounds);
    }

    _getRoundsFromBcryptHash(hash) {
        let rounds;
        if (hash) {
            const hashSegments = hash.split('$');
            if (hashSegments.length > 2) {
                rounds = parseInt(hashSegments[2], 10);
            }
        }
        return rounds;
    }

    _generateLoginToken(result) {
        if (!result) {
            throw new Error('result is required');
        }
        if (!result.userId && !result.error) {
            throw new Error('A login method must specify a userId or an error');
        }

        if (result.error) {
            throw new Error(result.error);
        }

        let stampedLoginToken = this._generateStampedLoginToken();

        let {userId} = result;
        this._insertLoginToken(userId, stampedLoginToken);

        let tokenExpiration = this._tokenExpiration(stampedLoginToken.when);

        return {
            id: userId,
            token: stampedLoginToken.token,
            tokenExpires: tokenExpiration,
        };
    }

    _generateStampedLoginToken() {
        return {
            token: random.generate({length: 43, charset: BASE64_CHARS}),
            when: new Date
        };
    }

    _tokenExpiration(when) {
        // We pass when through the Date constructor for backwards compatibility;
        // `when` used to be a number.
        return new Date((new Date(when)).getTime() + this._getTokenLifetimeMs());
    }

    _getTokenLifetimeMs() {
        // When loginExpirationInDays is set to null, we'll use a really high
        // number of days (LOGIN_UNEXPIRABLE_TOKEN_DAYS) to simulate an
        // unexpiring token.
        const loginExpirationInDays =
            (this._options.loginExpirationInDays === null)
                ? LOGIN_UNEXPIRING_TOKEN_DAYS
                : this._options.loginExpirationInDays;
        return (loginExpirationInDays
            || DEFAULT_LOGIN_EXPIRATION_DAYS) * 24 * 60 * 60 * 1000;
    }

    ///
    /// RECONNECT TOKENS
    ///
    /// support reconnecting using a meteor login token
    _hashLoginToken(loginToken) {
        const hash = createHash('sha256');
        hash.update(loginToken);
        return hash.digest('base64');
    };

    // {token, when} => {hashedToken, when}
    _hashStampedToken(stampedToken) {
        const hashedStampedToken = Object.keys(stampedToken).reduce(
            (prev, key) => key === 'token' ?
                prev :
                {...prev, [key]: stampedToken[key]},
            {},
        );
        return {
            ...hashedStampedToken,
            hashedToken: this._hashLoginToken(stampedToken.token)
        };
    };

    // Using $addToSet avoids getting an index error if another client
    // logging in simultaneously has already inserted the new hashed
    // token.
    _insertHashedLoginToken(userId, hashedToken, query) {
        query = query ? {...query} : {};
        query._id = userId;
        this.account.updateOne(query, {
            $addToSet: {
                "services.resume.loginTokens": hashedToken
            }
        }, function (err, res) {
            if (err) {
                throw new Error(err);
            }
        });
    };

    // Exported for tests.
    _insertLoginToken(userId, stampedToken, query) {
        this._insertHashedLoginToken(
            userId,
            this._hashStampedToken(stampedToken),
            query
        );
    };

    _clearAllLoginTokens(userId) {
        this.account.updateOne(userId, {
            $set: {
                'services.resume.loginTokens': []
            }
        }, function (err, res) {
            if (err) {
                throw new Error(err);
            }
        });
    };

    createUser(options) {
        let self = this;
        check(options, {
            username: {type: 'string'},
            email: {type: 'email', required: false}
        });

        if (options.password) {
            // 'password' is an object
            if (typeof options.password === "object") {
                check(options.password, {
                    algorithm: {type: 'string'},
                    digest: {type: 'string'}
                });
            } else {
                let passowrd = options.password;
                check({passowrd}, {passowrd: {type: 'string'}});
            }
        }

        const {username, email, password} = options;
        if (!username && !email)
            throw new Error("Need to set a username or email");

        const user = {createdAt: new Date(), _id: random.generate(20), services: {}};
        if (password) {
            const hashed = self._hashPassword(password);
            user.services.password = {bcrypt: hashed};
        }

        if (username)
            user.username = username;
        if (email)
            user.emails = [{address: email, verified: false}];
        let fullUser = _.assign(user, _.omit(options, ['username', 'email', 'password']));
        return new Promise((resolve, reject) => {
            self.account.create(fullUser).then(resolve).catch(reject);
        })
    }

    async loginWithPassword(options) {

        let self = this;
        let cond, rule;
        if (options.hasOwnProperty('email')) {
            rule = {email: {type: 'email'}};
            cond = {'emails.address': options.email};
        } else {
            rule = {username: {type: 'string'}}
            cond = {username: options.username};
        }
        check(options, rule);
        if (typeof options.password === "object") {
            check(options.password, {
                algorithm: {type: 'string'},
                digest: {type: 'string'}
            });
        } else {
            let passowrd = options.password;
            check({passowrd}, {passowrd: {type: 'string'}});
        }
        let user = await self.account.findOne(cond);
        if (!user) {
            throw new Error(`User not found`);
        }
        let result = await self.checkPassword(user, options.password);
        return self._generateLoginToken(result);
    }

    async loginWithToken(options) {
        check(options, {resume: {type: 'string'}});

        const self = this;
        let hashedToken = self._hashLoginToken(options.resume);

        let user = await self.account.findOne({'services.resume.loginTokens.hashedToken': hashedToken});

        if (!user) {
            throw new Error('Token expired');
        }

        let token = _.find(user.services.resume.loginTokens, function (token) {
            return token.hashedToken === hashedToken;
        });

        let tokenExpires = self._tokenExpiration(token.when);
        if (new Date() >= tokenExpires) {
            throw new Error('Token expired');
        }

        return {
            userId: user._id,
            token: options.resume,
            tokenExpires: self._tokenExpiration(token.when)
        };
    }

    async changePassword(userId, oldPassword, newPassword) {
        check({userId}, {userId: {type: 'string'}});

        //check oldPassword
        if (typeof oldPassword === "object") {
            check(oldPassword, {
                algorithm: {type: 'string'},
                digest: {type: 'string'}
            });
        } else {
            check({oldPassword}, {oldPassword: {type: 'string'}});
        }

        //check newPassword
        if (typeof newPassword === "object") {
            check(newPassword, {
                algorithm: {type: 'string'},
                digest: {type: 'string'}
            });
        } else {
            check({newPassword}, {newPassword: {type: 'string'}});
        }


        const self = this;
        const user = await self.account.findById(userId);
        if (!user) {
            throw new Error("User not found");
        }

        if (!user.services || !user.services.password || (!user.services.password.bcrypt && !user.services.password.srp)) {
            throw new Error("User has no password set");
        }

        if (!user.services.password.bcrypt) {
            throw new Error("old password format " + JSON.stringify({
                format: 'srp',
                identity: user.services.password.srp.identity
            }));
        }
        const result = await self.checkPassword(user, oldPassword);
        if (result.error) {
            throw new Error(result.error);
        }

        const hashed = self._hashPassword(newPassword);
        await self.account.updateOne({_id: userId}, {
            $set: {'services.password.bcrypt': hashed},
            $pull: {
                'services.resume.loginTokens': {hashedToken: {$ne: 1}}
            }
        });
        return result;
    }

    async checkPassword(user, password) {
        if (typeof password === "object") {
            check(password, {
                algorithm: {type: 'string'},
                digest: {type: 'string'}
            });
        } else {
            check({passowrd}, {passowrd: {type: 'string'}});
        }

        let result = {
            userId: user._id
        };
        const self = this;
        const formattedPassword = self._getPasswordString(password);
        const hash = user.services.password.bcrypt;
        const hashRounds = self._getRoundsFromBcryptHash(hash);

        if (!await bcrypt.compare(formattedPassword, hash)) {
            result.error = 'Incorrect password';
        } else if (hash && self._options.bcryptRounds !== hashRounds) {
            // The password checks out, but the user's bcrypt hash needs to be updated.
            await self.account.updateOne({_id: user._id}, {$set: {'services.password.bcrypt': self._hashPassword(formattedPassword)}});
        }
        return result;
    }

    async resetPassword(token, newPlaintextPassword) {
        const self = this;
        check({token}, {token: {type: 'string'}});

        if (typeof newPlaintextPassword === "object") {
            check(newPlaintextPassword, {
                algorithm: {type: 'string'},
                digest: {type: 'string'}
            });
        } else {
            check({newPlaintextPassword}, {newPlaintextPassword: {type: 'string'}});
        }

        let hashedToken = self._hashLoginToken(token);

        let user = await self.account.findOne({'services.resume.loginTokens.hashedToken': hashedToken});

        if (!user) {
            throw new Error('Token expired.');
        }

        let currentToken = _.find(user.services.resume.loginTokens, function (token) {
            return token.hashedToken === hashedToken;
        });

        let tokenExpires = self._tokenExpiration(currentToken.when);
        if (new Date() >= tokenExpires) {
            throw new Error('Token expired.');
        }

        const update = {
            $set: {
                'services.password.bcrypt': self._hashPassword(newPlaintextPassword)
            },
            $unset: {'services.resume.loginTokens': 1}
        };
        await self.account.updateOne({_id: user._id}, update);
        return {userId: user._id};
    }

    async setPassword(userId, newPlaintextPassword) {
        check({userId}, {userId: {type: 'string'}});

        if (typeof newPlaintextPassword === "object") {
            check(newPlaintextPassword, {
                algorithm: {type: 'string'},
                digest: {type: 'string'}
            });
        } else {
            check({newPlaintextPassword}, {newPlaintextPassword: {type: 'string'}});
        }

        const self = this;
        const user = await self.account.findById(userId);
        if (!user) {
            throw new Error("User not found");
        }

        const update = {
            $set: {'services.password.bcrypt': self._hashPassword(newPlaintextPassword)},
            $unset: {'services.resume.loginTokens': 1}
        };
        await self.account.updateOne({_id: user._id}, update);
        return {userId: user._id};
    }
}

module.exports = Account;