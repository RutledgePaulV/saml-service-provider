(ns buddy-saml-service-provider.core-test
  (:require [clojure.test :refer :all]
            [buddy-saml-service-provider.core :as bssp]
            [ring.adapter.jetty :as jetty]
            [ring.middleware.defaults :as defaults]
            [ring.middleware.session.memory :as memory]
            [clojure.java.io :as io]
            [clojure.pprint :as pprint]))

(defonce store (memory/memory-store))

(defn private-page [request]
  {:status  200
   :headers {"Content-Type" "text/plain"}
   :body    (with-out-str (pprint/pprint (:identity request)))})

(def settings
  {:onelogin.saml2.security.want_messages_signed     true
   :onelogin.saml2.security.want_assertions_signed   true
   :onelogin.saml2.security.authnrequest_signed      true
   :onelogin.saml2.security.sign_metadata            true
   :onelogin.saml2.security.logoutrequest_signed     true
   :onelogin.saml2.security.logoutresponse_signed    true
   :onelogin.saml2.organization.name                 "SP Java"
   :onelogin.saml2.organization.displayname          "SP Java Example"
   :onelogin.saml2.organization.url                  "http://sp.example.com"
   :onelogin.saml2.organization.lang                 "en"
   :onelogin.saml2.contacts.technical.given_name     "Technical Guy"
   :onelogin.saml2.contacts.technical.email_address  "technical@example.com"
   :onelogin.saml2.contacts.support.given_name       "Support Guy"
   :onelogin.saml2.contacts.support.email_address    "support@example.com"
   :onelogin.saml2.idp.single_logout_service.url     "http://localhost:7000/saml/slo"
   :onelogin.saml2.sp.single_logout_service.url      "http://localhost:3000/saml/confirm-logout"
   :onelogin.saml2.sp.assertion_consumer_service.url "http://localhost:3000/saml/acs"
   :onelogin.saml2.sp.entityid                       "http://localhost:3000"
   :onelogin.saml2.sp.x509cert                       (slurp (io/resource "sp-public-cert.pem"))
   :onelogin.saml2.sp.privatekey                     (slurp (io/resource "sp-private-key.pem"))
   :onelogin.saml2.idp.x509cert                      (slurp (io/resource "idp-public-cert.pem"))
   :onelogin.saml2.idp.single_sign_on_service.url    "http://localhost:7000/saml/sso"
   :onelogin.saml2.idp.entityid                      "urn:example:idp"})

(defn wrap-default-middleware [handler]
  (let [options (-> defaults/site-defaults
                    (assoc-in [:security :anti-forgery] false)
                    (assoc-in [:session :store] store))]
    (defaults/wrap-defaults handler options)))

(defn application [request]
  (let [config {:onelogin-settings settings}]
    ((-> private-page
         (bssp/wrap-saml-authentication config)
         (wrap-default-middleware))
     request)))

(defn create-server []
  (let [opts {:port 3000 :join? false}]
    (jetty/run-jetty (fn [req] (#'application req)) opts)))

(defonce server (atom nil))

(defn restart []
  (alter-var-root #'store (constantly (memory/memory-store)))
  (swap! server
         (fn [old]
           (when (some? old)
             (.stop old))
           (create-server))))