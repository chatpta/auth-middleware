const assert = require( 'assert' ).strict;
const Jwt = require( '../lib/Jwt' );
const keys = require( './keys/keys' );


describe( 'Test JWT token', function () {
    const jwt = new Jwt( keys );

    describe( 'Create and deconstruct jwt', function () {

        const header = {
            alg: "HS256",
            type: "jwt"
        };

        const payload = {
            sub: "1234567890",
            name: "John Doe",
            iat: 1516239022
        };

        it( 'creates jwt', function ( done ) {
            let token = jwt.createJWT( header, payload );
            let recreated = jwt.readJWT( token );

            assert.deepStrictEqual( recreated.header, header, 'JWT is not read properly' );
            assert.deepStrictEqual( recreated.payload, payload, 'JWT is not read properly' );
            done();
        } );

    } );
} );

