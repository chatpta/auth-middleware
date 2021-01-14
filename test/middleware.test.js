const assert = require('assert');
const AuthUtil = require('@petercraftsmn/auth-util');
const Middleware = require('../lib/middleware');
const middleware = new Middleware();
const authUtil = new AuthUtil({
    defaultAlgorithm: 'sha512',
    defaultSecret: 'dev-secret',
    defaultOutputType: 'base64',
});


describe('Middleware test Jwt functions', function () {
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
    let req = {
        'Authorization': 'Bearer ' + token,
        get: function (headerName) {
            if (headerName === 'Authorization') return this[headerName];
            else {
                return false;
            }
        }
    };


    describe('Testing jwt validation and attaching to req', function () {
        beforeEach(() => {
            req = {
                'Authorization': 'Bearer ' + token,
                get: function (headerName) {
                    if (headerName === 'Authorization') return this[headerName];
                    else {
                        return false;
                    }
                }
            };
        });

        it('Jwt token incoming in req.header.Authorization undefined', function (done) {
            req = {...reqOriginal, 'Authorization': undefined};
            middleware.validateJwtToken(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, null,
                'Jwt token is not null');
            done();
        });

        it('Jwt token incoming in req.header.Authorization null', function (done) {
            req = {...reqOriginal, 'Authorization': null};
            middleware.validateJwtToken(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, null,
                'Jwt token is not null');
            done();
        });

        it('Jwt token incoming in req.header.Authorization ""', function (done) {
            req = {...reqOriginal, 'Authorization': ''};
            middleware.validateJwtToken(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, null,
                'Jwt token is not null');
            done();
        });

        it('Jwt token incoming in req.header.Authorization ""', function (done) {
            req = {...reqOriginal, 'Authorization': 'Bearer '};
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
        beforeEach(() => {
            req = {
                'Authorization': 'Bearer ' + token,
                get: function (headerName) {
                    if (headerName === 'Authorization') return this[headerName];
                    else {
                        return false;
                    }
                }
            };
        });

        it('Check the signatures of jwt token', function (done) {
            middleware.validateJwtToken(req, res, nextFunc);
            middleware.validateJwtSignature(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, token,
                'Token signatures are not good');
            done();
        });

        it('Check the signatures of tempered token', function (done) {
            req = {...reqOriginal, 'Authorization': 'Bearer ' + token + 'somecrap'};
            middleware.validateJwtToken(req, res, nextFunc);
            middleware.validateJwtSignature(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtToken, null,
                'Token signatures are not good');
            done();
        });
    });

    describe('Testing jwt parsing', function () {
        beforeEach(() => {
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

    describe('Testing create jwt token', () => {
        beforeEach(() => {
            req = {
                header: {alg: "sha512"},
                payload: {name: "peter singh", id: "128837730383"}
            };
        });

        it('Create jwt', () => {
            middleware.createJwtToken(req, res, nextFunc);
            assert.ok(req.jwtToken.length > 30, 'jwtToken not created');
        });
    });

});

describe('Middleware test user functions', function () {
    let nextFunc = function (req, res) {
    };
    let res = {};
    let req = {};


    describe('Testing validation of username and password', function () {
        beforeEach(() => {
            req = {
                body: {
                    email: "validUsernamePassTest@gmail.com",
                    password: "secre*77pass"
                }
            };
        });

        it('Email and password incoming are well and good', function (done) {
            middleware.validateUsernamePassword(req, res, nextFunc);
            assert.deepStrictEqual(req.incomingUser.email, "validUsernamePassTest@gmail.com",
                'Both emails are not same');
            assert.deepStrictEqual((!req.error), true,
                'Bad password is not caught');
            done();
        });

        it('Email and password incoming are not well and good', function (done) {
            req.body.email = "bad @gmail.com";
            middleware.validateUsernamePassword(req, res, nextFunc);
            assert.ok((!!req.error), 'Bad email is not caught');
            done();
        });

        it('Email and password incoming are not well and good', function (done) {
            req.body.password = "verybad>>pass hehhe ";
            middleware.validateUsernamePassword(req, res, nextFunc);
            assert.ok((!!req.error), 'Bad password is not caught');
            done();
        });
    });

    describe('User login test', function () {
        beforeEach(() => {
            req = {
                body: {
                    email: "validUsernamePassTest@gmail.com",
                    password: "secre*77pass"
                }
            };
        });

        it('Verify user for login', function (done) {
            middleware.validateUsernamePassword(req, res, nextFunc);
            req = {
                ...req, databaseUser: {
                    user_id: 275537836663,
                    email: "validUsernamePassTest@gmail.com",
                    hash: authUtil.createPasswordHash("secre*77pass", authUtil.createRandomSalt())
                }
            };
            middleware.verifyUserForLogin(req, res, nextFunc);
            assert.deepStrictEqual(req.user.email, "validUsernamePassTest@gmail.com",
                'Both emails are not same');
            assert.deepStrictEqual(req.user.user_id, 275537836663,
                'Both user_id are not same');
            assert.deepStrictEqual((!req.error), true,
                'There is error');
            done();
        });
    });

});