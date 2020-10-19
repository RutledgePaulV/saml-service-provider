[![Clojars Project](https://img.shields.io/clojars/v/org.clojars.rutledgepaulv/saml-service-provider.svg)](https://clojars.org/org.clojars.rutledgepaulv/saml-service-provider)

Ring handlers/middleware for implementing saml authentication. Delegates to onelogin/java-saml for the actual xml
validation and parsing. Many thanks to the onelogin team for saving me from the hard parts!

---

### Usage

Here is an example of wiring this middleware into a ring app. Note that ring.middleware.anti-forgery is monkey-patched
by this library (if present)
to exempt your SAML endpoints that consume form posts from an IDP.

```clojure 

(require '[saml-service-provider.core :as sspc])
(require '[ring.middleware.defaults :as defaults])
(require '[ring.adapter.jetty :as jetty])
(require '[clojure.java.io :as io])

(defn whoami-handler [request]
  (let [saml-data  (:saml-service-provider.core/identity request)
        email-addr (get-in saml-data [:email 0])]
    {:status  200
     :headers {"Content-Type" "text/plain"}
     :body    (format "You're authenticated as %s" email-addr)}))

(def settings
  {:idp-metadata-url
   "http://localhost:7000/metadata"
   :onelogin-settings
   {:onelogin.saml2.sp.x509cert   (slurp (io/resource "sp-public-cert.pem"))
    :onelogin.saml2.sp.privatekey (slurp (io/resource "sp-private-key.pem"))}})

(def application
  (-> whoami-handler
      (sspc/wrap-saml-authentication settings)
      (defaults/wrap-defaults defaults/site-defaults)))

(jetty/run-jetty #'application {:port 3000 :join? false})

```

Default endpoints are:

``` 

INITIATE LOGIN: 
 /saml/login

ACS CALLBACK: 
 /saml/acs

SP METADATA:
 /saml/metadata

INITIATE LOGOUT:
 /saml/initiate-logout

LOGOUT CALLBACK:
 /saml/confirm-logout
 
```

---

### SAML Metadata

This library serves service provider metadata based on your configuration and also supports configuring the
authentication middleware using either an idp metadata url or explicit idp settings. I recommend using metadata on both
sides because it greatly reduces the burden of SAML setup and miscommunications.

---

### Options

Valid options are exactly those offered by [onelogin/java-saml](https://github.com/onelogin/java-saml#properties-file).

This library does provide [default values](./resources/saml-default-settings.edn) for many options.

---

### License

This project is licensed under [MIT license](http://opensource.org/licenses/MIT).
