/******************************************************************************
 * Copyright (c) 2020.  Peter Craftsmn                                        *
 * Written by Peter Craftsmn                                                  *
 * peter.craftsmn@gmail.com                                                   *
 ******************************************************************************/

const Cryptography = require('./Cryptography');


class Jwt extends Cryptography{
    constructor( keys ) {
        super( keys );
    }

    /**
     * Creates signed encrypted and url safe jwt
     * @param header
     * @param payload
     * @returns {string}
     */
    createJWT( header = '', payload = '' ) {

        const header_payload = JSON.stringify( header ) + '.' + JSON.stringify( payload );
        // Sign token last

        const encrypted_header_payload = this.encryptString( header_payload );
        const signature = this.signToken( encrypted_header_payload );
        const url_unsafe_token = encrypted_header_payload + '.' + signature;
        return this.makeStringUrlSafe( url_unsafe_token );

    };

    /**
     * Decrypts verifies and read the token back
     * @param jwt
     * @returns {{payload: *, header: *}|{message: string}}
     */

    readJWT( jwt = '' ) {

        if ( jwt.length > 50 ) {
            const url_unsafe_token = this.reverseStringUrlSafe( jwt );

            // Verify signature in the beginning
            const split_token = url_unsafe_token.split( '.' );
            const encrypted_header_payload = split_token[ 0 ];
            const signature = split_token[ 1 ];

            // Check signature
            if ( this.verifySignature( encrypted_header_payload, signature ) ) {
                const header_payload = this.decryptString( encrypted_header_payload );
                const split_header_payload = header_payload.split( '.' );
                return {
                    header: JSON.parse( split_header_payload[ 0 ] ),
                    payload: JSON.parse( split_header_payload[ 1 ] )
                }
            } else {
                return { header: false, payload: "token error" }
            }

        } else {
            return { header: false, payload: "token error" }
        }
    };

    /**
     * Creates a standard JWT for usage in any authentication
     * user object must contain user._id and user.type
     * returns null in case of error
     * @param user
     */
    createStandardJWT( user ) {

        if (
            user === undefined ||
            user === null ||
            user === '' ||
            user._id === undefined ||
            user._id === null ||
            user._id === '' ||
            user.type === undefined ||
            user.type === null ||
            user.type === ''
        ) {
            return null;
        } else {
            return this.createJWT(
                { type: "jwt" },
                {
                    _id: user._id,
                    type: user.type
                },
            );
        }
    };

}

module.exports = Jwt;
