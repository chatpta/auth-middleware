/******************************************************************************
 * Copyright (c) 2020.  Peter Craftsmn                                        *
 * Written by Peter Craftsmn                                                  *
 * peter.craftsmn@gmail.com                                                   *
 ******************************************************************************/

/**
 * This class methods should be used to make req.user object to looks as follows
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
 * Incoming webToken, username, password may be in the header or in the body.
 * These methods should extract them and attache to req.user object
 */

class AuthUtil {
    /**
     * Get the token from 'Authorization' header and attach it to req.user.webToken
     * @param req
     * @returns {Promise<void>}
     */
    async parseWebTokenFromAuthorizationHeader( req ) {
        if ( req.get( 'Authorization' ) === undefined ||
            req.get( 'Authorization' ) === null ) {
            req.user = null;
            req.erroCode = 'AUTHORIZATION_HEADER_DOES_NOT_CONTAIN_TOKEN';
        } else {
            req.user = { webToken: '' };
            req.user.webToken = await req.get( 'Authorization' );
        }
    }

}

module.exports = AuthUtil;

