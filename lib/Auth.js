/******************************************************************************
 * Copyright (c) 2020.  Peter Craftsmn                                        *
 * Written by Peter Craftsmn                                                  *
 * peter.craftsmn@gmail.com                                                   *
 ******************************************************************************/

const Crypt = require('./Jwt' );

/**
 * This class works on req.user object if this is as below
 * req object should looks as follows
 * some attributes may be missing
 * {
 *     req: {
 *         user: {
 *             username: "some username",
 *             password: "some password",
 *             id: "some id string",
 *             type: "some user type",
 *             salt: "some salt string",
 *             hash: "password and salt hash string",
 *             .
 *             .
 *             .
 *             storedUser: "user stored in database",
 *             token: {
 *                 header: "some token header",
 *                 payload: "some token payload"
 *             },
 *             webToken: "some web token string including signature string",
 *             webTokenSignature: "some signature string"
 *         }
 *     }
 * }
 *
 * req.user.token -> contain token object
 * req.user.webToken -> contain web token to be sent to received from user
 */
class Auth extends Crypt {
    constructor( keys ) {
        super( keys );
    }

    /**
     * Create random salt string for any purpose
     * @param req
     */
    async createSalt( req ) {
        req.user.salt = await this.saltCreator();
    }

    /**
     * Create hash of password + salt -> hash and attach to request
     * req.user.password and req.user.salt should be present
     * @param req
     */
    async createPasswordHash( req ) {
        req.user.hash = await this.hashCreator( req.user.password + req.user.salt );
    }

    /**
     * Create salt and password + salt -> hash and attache to req
     * req.user.password should contain password
     * @param req
     */
    async createSaltAndPasswordHash( req ) {
        req.user.salt = await this.saltCreator();
        req.user.hash = await this.hashCreator( req.user.password + req.user.salt );
    }

    /**
     * Create encrypted and signed user token and attach to req.user.webToken
     * req should contain
     * @param req
     */
    async createWebTokenSignedEncrypted( req ) {
        req.user.webToken = await this.createJWT( { type: "web" },
            {
                id: req.user.id,
                timeCreated: Date.now()
            } );
    }

    /**
     * Decrypt signed web token
     * @param req
     */
    async decryptWebTokenSignedEncrypted( req ) {
        const token = await this.readJWT( req.user.webToken );

        if ( token !== 'undefined' && token !== null &&
            token.header !== 'undefined' && token.header !== false &&
            token.payload !== 'undefined' && token.payload !== null &&
            token.payload.id !== 'undefined' && token.payload.id !== null &&
            token.payload.id !== '' ) {
            req.user.id = token.payload.id;
            req.user.token = token;
        } else {
            req.user = null
        }
    }

    /**
     * Create base64 signed user token and attach to req.user.webToken
     * req should contain
     * @param req
     */
    async createWebTokenSignedBase64( req ) {

        // Create token object
        req.user.token = {
            header: { type: "web" },
            payload: {
                id: req.user.id,
                timeCreated: Date.now()
            }
        };

        // Create signature string base 64
        req.user.webTokenSignature = await this.signToken( JSON.stringify( req.user.token ) );

        // Add both strings using '.' as separator
        const combinedTokenString = await this.asciiToBase64( JSON.stringify( req.user.token ) ) +
            '.' + req.user.webTokenSignature;

        // Make url safe and add to req.user.token
        req.user.webToken = await this.makeStringUrlSafe( combinedTokenString );
    }

    /**
     * Read base64 signed user token
     * @param req
     */
    async decryptVerifyWebTokenSignedBase64( req ) {

        // Reverse make url safe
        const combinedTokenString = await this.reverseStringUrlSafe( req.user.webToken );

        // Split string to token and signature string
        const splitTokenString = combinedTokenString.split( '.' );

        const tokenString = splitTokenString[ 0 ];
        req.user.webTokenSignature = splitTokenString[ 1 ];
        const decryptedTokenString = await this.base64ToAscii( tokenString );

        // Verify signature
        if ( this.verifySignature( decryptedTokenString, req.user.webTokenSignature ) ) {
            // Signature verified
            req.user.token = await JSON.parse( decryptedTokenString );
            req.user.id = req.user.token.payload.id;
        } else {
            // Signature not verified
            req.user = null;
        }
    }

    /**
     * Compare hash for login
     * User has been found by username and attached to req.user.storedUser
     * req.user.storedUser.hash contain stored hash of password
     * req.user.salt contain stored salt, it must be put here in advance from database
     * if hash comparison is true storedUser is merged in req.user and storedUser set to null
     * else req.user.id is set to null rest of the information is removed from req.user
     * @param req
     */
    async comparePasswordHash( req ) {
        if ( req.user !== 'undefined' &&
            req.user.hash !== 'undefined' &&
            req.user.hash !== null &&
            req.user.hash !== '' &&
            req.user.storedUser !== 'undefined' &&
            req.user.storedUser.hash !== 'undefined' &&
            req.user.storedUser.hash !== null &&
            req.user.storedUser.hash !== '' &&
            req.user.hash === req.user.storedUser.hash ) {
            req.user = await { ...req.user.storedUser };
        } else {
            req.user = await null;
        }
    }
}


module.exports = Auth;
