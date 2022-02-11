# JWT

A simple PHP library to work with JSON Web Token

## Documentation

### Generate token
```php
$secret = "fe1a1915a379f3be5394b64d14794932";
$jwt = JWT::newJWT($secret, "HS256"); // [HS256,HS384,HS512]
# $jwt->setKey("ZmUxYTE5MTVhMzc5ZjNiZTUzOTRiNjRkMTQ3OTQ5MzI", true); // secret base64 encoded
$jwt->addRule("iss", "User");
$jwt->addRule("sub", "1");
$jwt->addRule("name", "Farasource");
$jwt->addRule("iat", time());
$_jwt = $jwt->getJWT();
echo $_jwt;
```

### Validation
```php
$secret = "fe1a1915a379f3be5394b64d14794932";
$jwt = JWT::newJWT($secret, "HS256"); // [HS256,HS384,HS512]
$_jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6IkZhcmFzb3VyY2UiLCJpYXQiOjE2NDQ1NzI0Nzl9.-P0nwJkY3u2_K-3suShrvbHEv8thHqizrA7A6lX1Dps';
if ($jwt->verifySign($_jwt)) {
  echo $jwt->getRule('name');
} else {
  echo 'Invalid Signature';
}
```
