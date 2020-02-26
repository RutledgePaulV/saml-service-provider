[![Clojars Project](https://img.shields.io/clojars/v/org.clojars.rutledgepaulv/saml-service-provider.svg)](https://clojars.org/org.clojars.rutledgepaulv/saml-service-provider)

Ring handlers for implementing saml authentication with buddy auth. 
Delegates to onelogin/java-saml for the actual xml validation and parsing.

---

### Install

```clojure
[org.clojars.rutledgepaulv/saml-service-provider "0.1.0"]
```

---

### Usage

[Please see the example server.](test/saml_service_provider/core_test.clj)

---

### Options

Valid options are exactly those used by [onelogin/java-saml](https://github.com/onelogin/java-saml).

---

### License

This project is licensed under [MIT license](http://opensource.org/licenses/MIT).