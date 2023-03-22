The benefit to JWT authentication and not using cookies/sessions for authentication is that it allows you to truly treat your React and Rails applications as separate applications that don't need to be hosted on the same domain.

Trade Offs
To secure our application further, we should set our tokens to expire and make sure our app is being served over HTTPS
Strictly speaking, yes, anything stored in local/session storage (which I'll call HTML5 Storage) could be stolen in a cross-site scripting (XSS) attack.

Strictly speaking, yes, anything stored in local/session storage (which I'll call HTML5 Storage) could be stolen in a cross-site scripting (XSS) attack. See this article.

There are a lot of moving parts to consider, however.

First, there are subtle differences in how HTML5 Storage and cookies are scoped with respect to JavaScript access.

HTML5 Storage is:

1. divided between HTTP and HTTPS. An item stored in http://example.com HTML5 storage cannot be accessed by JavaScript running on https://example.com.
2. divided between subdomains. An item stored in http://example.com HTML5 storage cannot be accessed by JavaScript running on http://sub.example.com (you can do some tricks to get around this, however).





When using token based authentication you have to manually associate the token with the request. Contrary to cookies, tokens are not set automatically by the browser thus not susceptible to csrf attacks.

While this approach is safe from csrf attacks, it is susceptible to xss attacks.

A minimal effort improvement would be to use session storage instead of local storage since session storage data gets purged after the user closes the tab/browser.


BCrypt
BCrypt allows us to saltLinks to an external site. users' plaintext passwords before running them through a hashing function.
A hashing function is, basically, a one way function.
We then store these passwords that have been 'digested' by BCrypt in our database.
It's a bad idea to store plaintext passwords in your database.

```
    BCrypt::Password.create('P@ssw0rd')
```

- BCrypt::Password inherits from the Ruby String classLinks to an external site. and has its own == instance methodLinks to an external site. that allows us to run a plaintext password through BCrypt using the same salt and compare it against an already digested password

- BCrypt also provides a method that will take a stringified password_digest and turn it into an instance of BCrypt::Password, allowing us to call the over-written == method

- We have no way of storing instances of BCrypt::Password in our database. Instead, we're storing users' password digests as strings


# JSON Web Tokens (JWT)

JSON Web Token(JWT) is an open standard ([RFC 7519](https://tools.ietf.org/html/rfc7519)) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object.  
This information can be verified and trusted because when a JWT is created, they are digitally signed.

JWTs can be signed using a secret (with the **HMAC** algorithm) or a public/private key paair using RSA or ECDSA.  

**```HMAC - Hash Based Message Authentication```** is a cryptographic authentication technique that uses a hash function and a secret key. 

A pair of parties using this system must agree on:
- Secret Keys - Both parties must agree on a secret and hidden key for encoding and decoding messages.
- Algorithm - A hash function (SHA-1, MD5, SHA256, SHA512) that all these messages have to pass through to succesfully validate if a message hasn't been tampered with.

Signing the token allows its recipient to validate that the content of the token wasn't changed and verify that the original issuer of the token created the signature.

Token based authentication is stateless.
No information is being stored about a logged in user on the server implying that we don't need a model or table for user sessions.
When no information is stored, our application can scale and add more machines as necessary without worrying about where a user is logged in.  
The client browser is responsible for storing the token and sends that token along with every authenticated request.
Instead of storing a plaintext username, or user_id, **```we can encode user data with JSON Web Tokens (JWT) and store that encoded token client-side```**.

## JWT Authentication flow
1. An already existing user requests access with their username and password
2. The app validates these credentials
3. The app gives a signed token to the client
4. The client stores the token and presents it with every request. This token is effectively the user's access pass as it proves to the server that they are who they claim to be.

## JWT structure
```
    header.payload.signature  
    xxxxxx.yyyyyyyy.zzzzzzz
```
[JWT.IO](http://jwt.io/#debugger)
### Header
Consists of two parts: the **type of the token** and the **signing algorithm** being used.  
i.e. 
```
    {
        "alg": "HS256",
        "typ": "JWT"
    }
```
### Payload
Contains claims or statements about an entity.  
i.e. 
```
    {
        "sub": "1234567890",
        "name": "John Doe",
        "admin": true
    }
```
### Signature
To create the signature, we take the encoded header, the encoded payload, and a ```secret```
and sign the three using the algorithm specified in the **header** part of the payload.

****

## Encoding and Decoding JWTs in Rails

#### Prerequisite
* *jwt* gem  
```
$ bundle add jwt
```

##### JWT.encode
* Three Arguments
    - payload to encode
    - an application secret of the user's choice
    - hashing algorithm ```[optional]```
* Returns a JWT as a 'string'

##### JWT.decode
* Three Arguments
    - JWT as a string
    - an application secret
    - hashing algorithm ```[optional]```

***

    ```
    #in rails console
    payload = { beef: 'steak' }

    jwt = JWT.encode(payload, 'boeuf')
    # => "eyJhbGciOiJIUzI1NiJ9.eyJiZWVmIjoic3RlYWsifQ._IBTHTLGX35ZJWTCcY30tLmwU9arwdpNVxtVU0NpAuI"

    decoded_hash = JWT.decode(jwt, 'boeuf')
    # => [{"beef"=>"steak"}, {"alg"=>"HS256"}]

    data = decoded_hash[0]
    # => {"beef"=>"steak"}
    ```

## Building JWT functionality into the controllers
Given that many controllers will need to authenticate and authorize users, the functionality of encoding and encoding tokens is lifted to the top level ```ApplicationController``` since we subclass our controllers from this class.


```
class ApplicationController < ActionController::API
    def encode_token(payload)
        # payload => { beef: 'steak' }
        JWT.encode(payload, 'mysecret')
        # jwt string: "eyJhbGciOiJIUzI1NiJ9.eyJiZWVmIjoic3RlYWsifQ._IBTHTLGX35ZJWTCcY30tLmwU9arwdpNVxtVU0NpAuI"
    end

    def decode_token(token)
        # token => "eyJhbGciOiJIUzI1NiJ9.eyJiZWVmIjoic3RlYWsifQ._IBTHTLGX35ZJWTCcY30tLmwU9arwdpNVxtVU0NpAuI"

        JWT.decode(token, 'mysecret')[0]
        # JWT.decode => [{ "beef"=>"steak" }, { "alg"=>"HS256" }]
        # [0] gives us the payload { "beef"=>"steak" }
    end
end
```

Whenever the user wants to access a protected route or resource, the user agent should send the JWT, typically in the ```Authorization``` header using the ```Bearer``` schema.

```
Authorization: Bearer <token>
```

We can setup our server to anticipate a JWT sent along in request headers, instead of passing the token directly to ```ApplicationController#decoded_token```.

```
def decoded_token
    if auth_header
      token = auth_header.split(' ')[1]
      # headers: { 'Authorization': 'Bearer <token>' }
      begin
        JWT.decode(token, 'my_s3cr3t', true, algorithm: 'HS256')
        # JWT.decode => [{ "beef"=>"steak" }, { "alg"=>"HS256" }]
      rescue JWT::DecodeError
        nil
      end
    end
end
```
**The Begin/Rescue syntax allows us to rescue out of an exception in Ruby. In the event our server receives and attempts to decode an invalid token.**

