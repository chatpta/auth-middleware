const assert = require( 'assert' ).strict;
const keys = require( './keys/keys' );
const Auth = require( '../lib/Auth' );


describe( 'Auth test', function () {
    const authPc = new Auth( keys );
    const userId = "kkjwhhwllwhwl3l3hh4lljssl";
    let req = {
        user: {
            username: "peter@example.com",
            password: "my-secret-password",
            id: userId
        }
    };

    afterEach( () => {
        req = {
            user: {
                username: "peter@example.com",
                password: "my-secret-password",
                id: userId
            }
        };
    } );

    describe( 'testing auth methods success and failure', function () {
        it( 'createSalt and attach to req', function ( done ) {
            authPc.createSalt( req )
                .then( () => {
                    assert.ok( req.user.salt, 'Salt is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createPasswordHash and attach to req', function ( done ) {
            authPc.createPasswordHash( req )
                .then( () => {
                    assert.ok( req.user.hash, 'Hash is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createSaltAndPasswordHash and attach to req', function ( done ) {
            authPc.createSaltAndPasswordHash( req )
                .then( () => {
                    assert.ok( req.user.salt, 'Salt is absent' );
                    assert.ok( req.user.hash, 'Hash is absent' );
                    done();
                } )
                .catch( done );
        } );

        it( 'createWebTokenSignedEncrypted and decryptWebTokenSignedEncrypted', function ( done ) {
            authPc.createWebTokenSignedEncrypted( req )
                .then( () => {
                    req.user.id = null;
                    assert.ok( req.user.webToken, 'webToken is absent' );
                } )
                .then( () => {
                    authPc.decryptWebTokenSignedEncrypted( req );
                } )
                .then( () => {
                    assert.equal( req.user.id, userId );
                    done();
                } )
                .catch( done );
        } );

        it( 'createWebTokenSignedEncrypted and decryptWebTokenSignedEncrypted should fail', function ( done ) {
            authPc.createWebTokenSignedEncrypted( req )
                .then( () => {
                    req.user.id = null;
                    assert.ok( req.user.webToken, 'webToken is absent' );
                    req.user.webToken = 'some_bad_text';
                } )
                .then( () => {
                    authPc.decryptWebTokenSignedEncrypted( req );
                } )
                .then( () => {
                    assert.strictEqual( req.user, null );
                    done();
                } )
                .catch( done );
        } );

        it( 'createWebTokenSignedBase64 and decryptWebTokenSignedBase64', function ( done ) {
            // console.log( req.user );
            authPc.createWebTokenSignedBase64( req )
                .then( async () => {
                    // Remove extra data from user object
                    req.user = { webToken: req.user.webToken };
                    await authPc.decryptVerifyWebTokenSignedBase64( req );
                } )
                .then( () => {
                    assert.deepStrictEqual( req.user.id, userId,
                        "Decrypted id is not same" );
                    done();
                } )
                .catch( done );
        } );

        it( 'createWebTokenSignedBase64 and decryptWebTokenSignedBase64 should fail', function ( done ) {
            // console.log( req.user );
            authPc.createWebTokenSignedBase64( req )
                .then( async () => {
                    // Remove extra data from user object
                    req.user = { webToken: 'bad_text' };
                    await authPc.decryptVerifyWebTokenSignedBase64( req );
                } )
                .then( () => {
                    assert.deepStrictEqual( req.user, null,
                        "User not null" );
                    done();
                } )
                .catch( done );
        } );

        it( 'comparePasswordHash', function ( done ) {
            authPc.createSaltAndPasswordHash( req )
                .then( () => {
                    // Emulate storedUser and username password coming from client
                    req.user.storedUser = { ...req.user, password: null };
                    req.user.id = null;
                    req.user.type = null;
                    req.user.hash = null;
                } )
                .then( () => {
                    authPc.createPasswordHash( req );
                } )
                .then( () => {
                    authPc.comparePasswordHash( req );
                } )
                .then( () => {
                    assert.strictEqual( req.user.id, userId, 'User id is not same' );
                    done();
                } )
                .catch( done );
        } );

        it( 'comparePasswordHash should fail', function ( done ) {
            authPc.createSaltAndPasswordHash( req )
                .then( () => {
                    // Emulate storedUser and username password coming from client
                    req.user.storedUser = { ...req.user, password: null, hash: 'wrong_hash' };
                    req.user.id = null;
                    req.user.type = null;
                    req.user.hash = null;
                } )
                .then( () => {
                    authPc.createPasswordHash( req );
                } )
                .then( () => {
                    authPc.comparePasswordHash( req );
                } )
                .then( () => {
                    assert.strictEqual( req.user, null, 'User is not null' );
                    done();
                } )
                .catch( done );
        } );
    } );

} );

