/******************************************************************************
 * Copyright (c) 2020.  Peter Craftsmn                                        *
 * Written by Peter Craftsmn                                                  *
 * peter.craftsmn@gmail.com                                                   *
 ******************************************************************************/

const assert = require( 'assert' ).strict;
const AuthUtil = require( '../lib/AuthUtil' );
const authUtil = new AuthUtil();

describe( 'AuthUtil test', () => {

    let req = {
        'Authorization': 'Some header',
        get: function ( headerName ) {
            if ( headerName === 'Authorization' ) return this[ headerName ];
            else {
                return false;
            }
        }
    };

    describe( 'testing auth util methods success and failure', () => {
        it( 'parses web token from Authorization Header', ( done ) => {
            authUtil.parseWebTokenFromAuthorizationHeader( req )
                .then( () => {
                    assert.deepStrictEqual( req.user.webToken, req.Authorization,
                        'Web token in not present.')
                    done();
                } )
                .catch( done )
        } );

    } );
} );
