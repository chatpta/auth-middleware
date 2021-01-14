# auth middleware

  This is middleware for jwt

## Installation

```bash
 npm install @petercraftsmn/auth-middleware
```

### Functions
- Creates jwt token from req.header and req.payload objects
- Attaches jwt to req.jwtToken property
- No error check except that both object exist
- If any of the object not exist calls next()
```js
createJwtToken(req, res, next)
```
- Expect jwt token in Authorization header with bearer schema
- If validation is successful 
  - req.jwtToken contains the token
- If can not validate sets values as follows 
  - req.jwtToken = null;
  - req.user = {message: "no token present", id: null, exist: false};
```js
validateJwtToken(req, res, next)
```

- Expect jwt token in req.jwtToken 
- calls next() if signatures are true
- sets req.jwtToken and req.user to null if false
```js
validateJwtSignature(req, res, next)
```

