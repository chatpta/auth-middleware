/******************************************************************************
 * Copyright (c) 2020.  Peter Craftsmn                                        *
 * Written by Peter Craftsmn                                                  *
 * peter.craftsmn@gmail.com                                                   *
 ******************************************************************************/
const Validate = require('@petercraftsmn/validate');
const AuthUtil = require('@petercraftsmn/auth-util');
const validate = new Validate();
const authUtil = new AuthUtil({
    defaultAlgorithm: 'sha512',
    defaultSecret: 'dev-secret',
    defaultOutputType: 'base64',
});


class Middleware {

    /**
     * Creates a jwt token and attach to req.jwtToken
     * @param req
     * @param res
     * @param next
     */
    createJwtToken(req, res, next) {
        if (!req.header || !req.payload) {
            req.jwtToken = null;
            next();
        } else {
            req.jwtToken = authUtil.createJWT(req.header, req.payload);
            next();
        }
    }

    /**
     * Validate incoming jwt token and attach to req.jwtToken
     * @param req
     * @param res
     * @param next
     */
    validateJwtToken(req, res, next) {
        if (!req.get('Authorization')) {
            req.jwtToken = null;
            req.user = {message: "no token present", id: null, exist: false};
            next();
        } else {
            let [schema, token] = req.get('Authorization').split(' ');
            if (schema.toLowerCase() === 'bearer' && token.length > 10) {
                req.jwtToken = token;
                next();
            } else {
                req.jwtToken = null;
                req.user = {message: "no token present", id: null, exist: false};
                next();
            }
        }
    };

    /**
     * This should run after validateJwtToken
     * @param req
     * @param res
     * @param next
     */
    validateJwtSignature(req, res, next) {
        if (req.jwtToken && !req.user && authUtil.verifySignatureJWT(req.jwtToken)) {
            next();
        } else {
            req.jwtToken = null;
            req.user = null;
            next();
        }
    }

    /**
     * Parses jwt token from Authorization header and attach to req.user
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    async parseJwtToken(req, res, next) {
        if (req.jwtToken && !req.user) {
            req.user = authUtil.readJWT(req.jwtToken);
            req.jwtToken = null;
            next();
        } else {
            next();
        }
    };

    /**
     * Verify input is correct type for username and password or email and password
     * If yes attaches it to the req.user.email and req.user.password
     * @param req
     * @param res
     * @param next
     */
    validateUsernamePassword(req, res, next) {
        if (((!validate.isEmail(req.body.email)) ||
            (!validate.isStringOfPassword(req.body.password)))) {
            req.body.email = null;
            req.body.password = null;
            req.error = {place: "validateUsernamePassword"};
            next();
        } else {
            req.incomingUser = {
                email: req.body.email,
                password: req.body.password
            };
            req.body.email = null;
            req.body.password = null;
            next();
        }
    }

    /**
     * Compares the hash of incoming password against stored hash
     * stored user should be in req.databaseUser{email: "email@gmail.com", hash: "soemehash"}
     * incoming user should be in req.incomingUser(email: "email@gmail.com", password: "secret"}
     * @param req
     * @param res
     * @param next
     */
    verifyUserForLogin(req, res, next) {
        if (authUtil.verifyPasswordHash(req.incomingUser.password, req.databaseUser.hash) &&
            req.incomingUser.email === req.databaseUser.email) {
            req.user = {
                user_id: req.databaseUser.user_id,
                email: req.databaseUser.email
            };
            req.incomingUser = null;
            req.databaseUser = null;
            next();
        } else {
            req.user = null;
            req.incomingUser = null;
            req.databaseUser = null;
            req.error = {place: "verifyIncomingPasswordHashAgainstStoredHash"};
            next();
        }
    }

}

module.exports = Middleware;