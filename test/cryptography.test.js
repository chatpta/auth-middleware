const Crypt = require( '../lib/Cryptography' );
const assert = require( 'assert' ).strict;
const keys = require( './keys/keys' );


describe( 'Cryptography tests', function () {
    const crypt = new Crypt( keys );

    describe( 'Create hash, salt', function () {

        it( 'Create the hash of string', function ( done ) {
            const test_hash = crypt.hashCreator( "some data to hash" );
            assert.ok( test_hash, 'Hash not created' );
            done();
        } );

        it( 'Create the random salt string', function ( done ) {
            assert.ok( crypt.saltCreator(), 'Salt not created' );
            done();
        } );
    } );

    describe( 'Encrypt a string', function () {
        const some_text = 'This is some text for encryption';

        it( 'Encrypt and decrypt given string', function ( done ) {
            const encrypted_text = crypt.encryptString( some_text );
            assert.ok( encrypted_text, 'Text not encrypted' );
            const decrypted_text = crypt.decryptString( encrypted_text );
            assert.equal( decrypted_text, some_text, 'Text not decrypted correctly' );

            // Altered or erroneous encrypted string
            const decrypted_text_altered = crypt.decryptString( encrypted_text + 'altered' );
            assert.deepStrictEqual(decrypted_text_altered, 'ERR_OSSL_EVP_WRONG_FINAL_BLOCK_LENGTH',
                'Wrong error code');
            done();
        } );
    } );

    describe( 'Make string URL safe', function () {

        const some_string = 'ivCpHhWvYpPfCUWJK+Ceqp06BcOheH/Ddvx6q8KqS8y/+QavX19AeOW9zfLze1m7zSB1';

        it( 'Removes + and / character and replace them with - and _', function ( done ) {
            const url_safe_string = crypt.makeStringUrlSafe( some_string );
            const url_unsafe_string = crypt.reverseStringUrlSafe( url_safe_string );

            assert.equal( url_unsafe_string, some_string, 'Url safe and reverse is not working properly' );
            done();
        } )
    } );

    describe( 'Sign and verify signature', function () {

        const some_text = "This is some text";
        const some_other_text = "This is text";

        it( 'sign and verify signatures', function ( done ) {
            const signature = crypt.signToken( some_text );
            // Correctly verify signature
            let result = crypt.verifySignature( some_text, signature );
            assert.equal( result, true, 'Signature not verified' );
            // Fail the verification because text is not same
            let fail_result = crypt.verifySignature( some_other_text, signature );
            assert.equal( fail_result, false, 'Signature verified' );
            done();
        } )
    } )

    describe( 'Create and verify base64 string', function () {

        const someText = "This is some text";

        it( 'create and verify base64', function ( done ) {
            const base64String = crypt.asciiToBase64( someText );
            let asciiString = crypt.base64ToAscii( base64String );
            assert.equal( asciiString, someText, 'Base64 not verified' );
            done();
        } )
    } )
} );


