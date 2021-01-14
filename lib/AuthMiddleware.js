/******************************************************************************
 * Copyright (c) 2020.  Peter Craftsmn                                        *
 * Written by Peter Craftsmn                                                  *
 * peter.craftsmn@gmail.com                                                   *
 ******************************************************************************/

const Auth = require( './Auth' );
const AuthUtil = require( './AuthUtil' );
const authUtil = new AuthUtil();

class AuthMiddleware {
    constructor( keys ) {
        this.auth = new Auth( keys );
    }

    /**
     * Reads the jwt from req
     * Parses and attaches the parsed_token.header and parsed_token.payload to req
     * @param req
     * @param res
     * @param next
     */
    async bodyJwtToUser( req, res, next ) {

        if ( req.body === undefined || req.body === null ) {
            req.parsed_token = null;
            req.user = { message: "no token present", id: null, exist: false };
            next();
        } else {
            if ( req.body.token !== undefined || typeof req.body.token === "string" ) {
                req.parsed_token = await this.auth.readJWT( req.body.token );
                this.attachUserToReq( req, res, next );
            } else {
                req.parsed_token = null;
                req.user = { message: "no token present", id: null, exist: false };
                next();
            }
        }
    };

    /**
     * Parses jwt token from Authorization header
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    async headerJwtToUser( req, res, next ) {

        if ( req.get( 'Authorization' ) === undefined || req.get( 'Authorization' ) === null ) {
            req.parsed_token = null;
            req.user = { message: "no token present", id: null, exist: false };
            next();
        } else {
            await authUtil.parseWebTokenFromAuthorizationHeader( req );
            req.parsed_token = await this.auth.readJWT( req.user.webToken );
            this.attachUserToReq( req, res, next );
        }

    };

    /**
     * Attaches user to request
     * @param req
     * @param res
     * @param next
     */
    attachUserToReq( req, res, next ) {
        if ( req.parsed_token.header === false ) {
            req.user = { message: "no token present", id: null, exist: false };
            next();
        } else {
            req.user = {
                message: null,
                id: req.parsed_token.payload.id,
                type: req.parsed_token.payload.type,
                exist: true
            };
            next();
        }
    }

    /**
     * Creates web token from req.{user.id, user.type} and attach to req.user.webToken
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    async createWebTokenUserIdAndType( req, res, next ) {
        if ( req.user === 'undefined' ||
            req.user.id === 'undefined' ||
            req.user.type === 'undefined' ) {
            next();
        } else {
            req.user.webToken = await this.auth.createJWT( { alg: "sha256" },
                {
                    id: req.user.id,
                    type: req.user.id
                } );
            next();
        }
    }
}

module.exports = AuthMiddleware;

