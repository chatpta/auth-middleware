/******************************************************************************
 * Copyright (c) 2020.  Peter Craftsmn                                        *
 * Written by Peter Craftsmn                                                  *
 * peter.craftsmn@gmail.com                                                   *
 ******************************************************************************/
const AuthUtil = require('@petercraftsmn/auth-util');
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

}

module.exports = Middleware;