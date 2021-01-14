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
- Expect jwt token in Authorization header
```js
validateJwtToken(req, res, next)
```