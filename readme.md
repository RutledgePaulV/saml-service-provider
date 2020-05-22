[![Clojars Project](https://img.shields.io/clojars/v/org.clojars.rutledgepaulv/saml-service-provider.svg)](https://clojars.org/org.clojars.rutledgepaulv/saml-service-provider)

Ring handlers for implementing saml authentication. Delegates to onelogin/java-saml for the actual xml validation and parsing.

---

### Usage

[Please see the example server.](test/saml_service_provider/core_test.clj)

Default endpoints are:

``` 
INITIATE LOGIN: 
 http://localhost:3000/saml/login

ACS CALLBACK: 
 http://localhost:3000/saml/acs

SP METADATA:
 http://localhost:3000/saml/metadata

INITIATE LOGOUT:
 http://localhost:3000/saml/initiate-logout

LOGOUT CALLBACK:
 http://localhost:3000/saml/confirm-logout
```

---

### Options

Valid options are exactly those offered by [onelogin/java-saml](https://github.com/onelogin/java-saml).

This library does provide [default values](./resources/saml-default-settings.edn) for many options.

---

### License

This project is licensed under [MIT license](http://opensource.org/licenses/MIT).
