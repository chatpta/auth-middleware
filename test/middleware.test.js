const AuthUtil = require('@petercraftsmn/auth-util');
const assert = require('assert');
const Middleware = require('../lib/middleware');

const authUtil = new AuthUtil({
    defaultAlgorithm: 'sha512',
    defaultSecret: 'dev-secret',
    defaultOutputType: 'base64',
});

const middleware = new Middleware();


describe('Middleware test', function () {
    let nextFunc = function (req, res) {
    };
    let header = {alg: "sha512"};
    let payload = {name: "peter singh", id: "128837730383"};
    let token = authUtil.createJWT(header, payload);
    let res = {};
    let reqOriginal = {
        'Authorization': 'Bearer ' + token,
        get: function (headerName) {
            if (headerName === 'Authorization') return this[headerName];
            else {
                return false;
            }
        }
    };
    let req = reqOriginal;


    describe('Testing jwt validation and attaching to req', function () {
        afterEach(() => {
            req = reqOriginal;
        });

        it('Jwt token incoming in req.header.Authorization undefined', function (done) {
            req = {...req, 'Authorization': undefined};
            middleware.validateJwtToken(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, null,
                'Jwt token is not null');
            done();
        });

        it('Jwt token incoming in req.header.Authorization null', function (done) {
            req = {...req, 'Authorization': null};
            middleware.validateJwtToken(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, null,
                'Jwt token is not null');
            done();
        });

        it('Jwt token incoming in req.header.Authorization ""', function (done) {
            req = {...req, 'Authorization': ''};
            middleware.validateJwtToken(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, null,
                'Jwt token is not null');
            done();
        });

        it('Jwt token incoming in req.header.Authorization ""', function (done) {
            req = {...req, 'Authorization': 'Bearer '};
            middleware.validateJwtToken(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, null,
                'Jwt token is not null');
            done();
        });

        it('Jwt token incoming in req.header.Authorization', function (done) {
            middleware.validateJwtToken(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, token,
                'Both jwt tokens are not same');
            done();
        });

    });

    describe('Testing jwt signature', function () {
        afterEach(() => {
            req = reqOriginal;
        });

        it('Check the signatures of jwt token', function (done) {
            middleware.validateJwtToken(req, res, nextFunc);
            middleware.validateJwtSignature(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, token,
                'Token signatures are not good');
            done();
        });

        it('Check the signatures of tempered token', function (done) {
            req = {...req, 'Authorization': 'Bearer ' + token + 'somecrap'};
            middleware.validateJwtToken(req, res, nextFunc);
            middleware.validateJwtSignature(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, null,
                'Token signatures are not good');
            done();
        });
    });

    describe('Testing jwt parsing', function () {
        afterEach(() => {
            req = reqOriginal;
        });

        it('Parse jwt token and attach to req.user', function (done) {
            middleware.validateJwtToken(req, res, nextFunc);
            middleware.parseJwtToken(req, res, nextFunc);
            assert.deepStrictEqual(req.user.payload,
                {name: "peter singh", id: "128837730383"},
                'User is not parsed');
            done();
        });
    });

});

