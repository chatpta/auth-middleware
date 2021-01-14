/******************************************************************************
 * Copyright (c) 2020.  Peter Craftsmn                                        *
 * Written by Peter Craftsmn                                                  *
 * peter.craftsmn@gmail.com                                                   *
 ******************************************************************************/

const crypto = require( 'crypto' );
const Keys = require( './Keys' );

class Cryptography extends Keys {
    constructor( keys ) {
        super( keys );
        this.encryptedOutputCoding = 'base64';
        this.hashAlgorithm = 'sha512';
        this.unEncryptedTextEncoding = 'utf8';
        this.cipherAlgorithm = 'aes-192-cbc';
        this.signingAlgorithm = 'SHA256';
        this.encryptionKey = crypto.scryptSync( this.privateKey, this.privateKey, 24 );
    }

    /**
     * Creates the base64 hash of given string
     * HMAC does not encrypt the message.
     * Every time same string with same key should give the same hash
     * outputs base64 string
     * @param string
     * @returns {string}
     */
    hashCreator( string = '' ) {
        return crypto.createHmac( this.hashAlgorithm, this.privateKey )
            .update( string )
            .digest( this.encryptedOutputCoding );
    };

    /**
     * Create random salt
     * Uses time as input to produce random string
     * @returns {string}
     */
    saltCreator() {
        return this.hashCreator( new Date().valueOf().toString() );
    };

    /**
     * Encrypt given string
     * Outputs base64 encoded encrypted string
     * @param inputString
     * @returns {string}
     */
    encryptString( inputString = '' ) {
        try {
            const iv = Buffer.alloc( 16, 0 );
            const cipher = crypto.createCipheriv( this.cipherAlgorithm, this.encryptionKey, iv );
            let encrypted = cipher.update( inputString, this.unEncryptedTextEncoding, this.encryptedOutputCoding );
            encrypted += cipher.final( this.encryptedOutputCoding );
            return encrypted;
        } catch ( error ) {
            return error.code;
        }
    };

    /**
     * Decrypts given string
     * @param encryptedString
     * @returns {string}
     */
    decryptString( encryptedString = '' ) {
        try {
            const iv = Buffer.alloc( 16, 0 );
            const decipher = crypto.createDecipheriv( this.cipherAlgorithm, this.encryptionKey, iv );
            let decrypted = decipher.update( encryptedString, this.encryptedOutputCoding, this.unEncryptedTextEncoding );
            decrypted += decipher.final( this.unEncryptedTextEncoding );
            return decrypted;
        } catch ( error ) {
            return error.code;
        }
    };

    /**
     * Removes / and + from the string
     * @param string
     * @returns {string}
     */
    makeStringUrlSafe( string = '' ) {
        const slash_removed = string.replace( /\//g, "_" );
        return slash_removed.replace( /\+/g, "-" );
    };

    /**
     * Put back / and + into the string
     * @param string
     * @returns {string}
     */
    reverseStringUrlSafe( string = '' ) {
        const slash_added = string.replace( /_/g, "/" );
        return slash_added.replace( /-/g, "+" );
    };

    /**
     * Signs a token given returns signature string
     * @param token
     * @returns {string}
     */
    signToken( token = '' ) {
        const sign = crypto.createSign( this.signingAlgorithm );
        sign.update( token );
        sign.end();
        return sign.sign( this.privateKey, this.encryptedOutputCoding );
    };

    /**
     * Verifies the signature returns true or false
     * @param token
     * @param signature
     * @returns {boolean}
     */
    verifySignature( token = '', signature = '' ) {
        const verify = crypto.createVerify( this.signingAlgorithm );
        verify.update( token );
        verify.end();
        return verify.verify( this.publicKey, signature, this.encryptedOutputCoding );
    };

    /**
     * Converts given string to base 64
     * @param string
     * @returns {string}
     */
    asciiToBase64( string = '' ) {
        return Buffer.from( string ).toString( 'base64' );
    }

    /**
     * Converts given base64 string to ascii string
     * @param string
     * @returns {string}
     */
    base64ToAscii( string = '' ) {
        return Buffer.from( string, 'base64' ).toString( 'ascii' );
    }
}

module.exports = Cryptography;
