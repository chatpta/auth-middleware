const assert = require( 'assert' ).strict;
const keys = require( './keys/keys' );
const JwtMiddleware = require( '../lib/AuthMiddleware' );
const Auth = require( '../lib/Auth' );
const auth = new Auth( keys );


describe( 'Auth middleware test', function () {
    const jwtMiddleware = new JwtMiddleware( keys );

    describe( 'testing auth middleware success and failure', function () {

        let nextFunc = function ( req, res ) {
        };

        it( 'Correct jwt token incoming in req.body.token', function ( done ) {

            let jwtHeader = { alg: "sha256" };
            let jwtBody = { name: "peter singh", id: "128837730383" };
            let token = auth.createJWT( jwtHeader, jwtBody );

            let req = {
                body: {
                    token: token
                }
            };

            let res = {};

            jwtMiddleware.bodyJwtToUser( req, res, nextFunc )
                .then( () => {
                    // console.log( req );
                    // console.log( req.parsed_token );
                    assert.deepStrictEqual( req.parsed_token.header.alg, jwtHeader.alg,
                        'Parsed jwt header are not same as given header' );
                    assert.deepStrictEqual( req.parsed_token.payload.id, jwtBody.id,
                        'Parsed jwt payload._id is not correct' );
                    done();
                } )
                .catch( err => done( err ) );
        } );

        it( 'Bad jwt token incoming in req.body.token', function ( done ) {

            let bad_token = 'chARxIg-3S6nr7molw8VQokZD7r-hzC1WXIR7IFNIiKIe47bscH9SCmJk3SAE_cDyDNVPd848QDj7i54' +
                '5BlMkSvi6Fqsnw-J1iP7XNb53npAiKYAboCSH9ZECYa5xyrJP-87ZQYbzY2zkNjzKDdIrc4m5bhi0hutchR_EHdg' +
                'l4Z9LVKtDAZ87NAAZ8x4i4SDEYENKa7l6UwH-md6kbbKXnfSHG5Z-y8ksqlWnY2II-NXRvbHjZxRz20mKjrRFYGI' +
                'aWKXASvAghPI_xNBq9SddPk16TX9n-QEk5m6F7ozoslJhmt0alXCuvW0L-EdQMfveSj9koY1I6Mr9q1lxEvbflUT' +
                'DrNw2v-MS90k=';

            let req = {
                body: {
                    token: bad_token
                }
            };

            let res = {};

            jwtMiddleware.bodyJwtToUser( req, res, nextFunc )
                .then( () => {
                    // console.log( req );
                    assert.strictEqual( req.parsed_token.header, false,
                        'Parsed jwt header is not false for wrong token' );
                    assert.strictEqual( req.parsed_token.payload, 'token error',
                        'Token error is not present' );
                    done();
                } )
                .catch( err => done( err ) );
        } );

        it( 'Undefined req.body.token', function ( done ) {

            let req = { body: null };

            let res = {};

            jwtMiddleware.bodyJwtToUser( req, res, nextFunc )
                .then( () => {
                    // console.log( req );
                    assert.strictEqual( req.user.id, null,
                        'Parsed user.id is not null' );
                    done();
                } )
                .catch( err => done( err ) );
        } );

        it( 'Correct jwt token incoming in req.header.Authorization', function ( done ) {

            let jwtHeader = { alg: "sha256" };
            let jwtBody = { name: "peter singh", id: "128837730383" };
            let token = auth.createJWT( jwtHeader, jwtBody );

            let req = {
                'Authorization': token,
                get: function ( headerName ) {
                    if ( headerName === 'Authorization' ) return this[ headerName ];
                    else {
                        return false;
                    }
                }
            };

            let res = {};

            jwtMiddleware.headerJwtToUser( req, res, nextFunc )
                .then( () => {
                    // console.log( req );
                    // console.log( req.parsed_token );
                    assert.deepStrictEqual( req.parsed_token.header.alg, jwtHeader.alg,
                        'Parsed jwt header are not same as given header' );
                    assert.deepStrictEqual( req.parsed_token.payload.id, jwtBody.id,
                        'Parsed jwt payload._id is not correct' );
                    done();
                } )
                .catch( err => done( err ) );
        } );

        it( 'Bad jwt token incoming in req.header.Authorization', function ( done ) {

            let bad_token = 'chARxIg-3S6nr7molw8VQokZD7r-hzC1WXIR7IFNIiKIe47bscH9SCmJk3SAE_cDyDNVPd848QDj7i54' +
                '5BlMkSvi6Fqsnw-J1iP7XNb53npAiKYAboCSH9ZECYa5xyrJP-87ZQYbzY2zkNjzKDdIrc4m5bhi0hutchR_EHdg' +
                'l4Z9LVKtDAZ87NAAZ8x4i4SDEYENKa7l6UwH-md6kbbKXnfSHG5Z-y8ksqlWnY2II-NXRvbHjZxRz20mKjrRFYGI' +
                'aWKXASvAghPI_xNBq9SddPk16TX9n-QEk5m6F7ozoslJhmt0alXCuvW0L-EdQMfveSj9koY1I6Mr9q1lxEvbflUT' +
                'DrNw2v-MS90k=';

            let req = {
                'Authorization': bad_token,
                get: function ( headerName ) {
                    if ( headerName === 'Authorization' ) return this[ headerName ];
                    else {
                        return false;
                    }
                }
            };

            let res = {};

            jwtMiddleware.headerJwtToUser( req, res, nextFunc )
                .then( () => {
                    // console.log( req );
                    assert.strictEqual( req.parsed_token.header, false,
                        'Parsed jwt header is not false for wrong token' );
                    assert.strictEqual( req.parsed_token.payload, 'token error',
                        'Token error is not present' );
                    done();
                } )
                .catch( err => done( err ) );
        } );

        it( 'Undefined req.header.Authorization', function ( done ) {

            let req = {
                'Authorization': null,
                get: function ( headerName ) {
                    if ( headerName === 'Authorization' ) return this[ headerName ];
                    else {
                        return false;
                    }
                }
            };

            let res = {};

            jwtMiddleware.headerJwtToUser( req, res, nextFunc )
                .then( () => {
                    // console.log( req );
                    assert.strictEqual( req.user.id, null,
                        'Parsed user._id is not null' );
                    done();
                } )
                .catch( err => done( err ) );
        } );

        it( 'Creates web token and attaches to user object', ( done ) => {
            let req = {
                user: { type: [ 1, 2 ], id: "128837730383" }
            };

            let res = {};

            jwtMiddleware.createWebTokenUserIdAndType( req, res, nextFunc )
                .then( () => {
                    assert.ok( req.user.webToken );
                    done();
                } )
                .catch( done );
        } )
    } );

} );

