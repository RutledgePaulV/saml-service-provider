(ns buddy-saml-service-provider.core-test
  (:require [clojure.test :refer :all]
            [buddy-saml-service-provider.core :as bssp]
            [ring.adapter.jetty :as jetty]
            [ring.util.codec :as codec]
            [clojure.string :as strings]
            [buddy.auth.backends :as bb]
            [buddy.auth.middleware :as bmw]
            [ring.middleware.defaults :as defaults]
            [buddy.auth :as buddy]
            [ring.util.response :as response]
            [ring.util.response :as response]
            [ring.middleware.session.memory :as memory]
            [clojure.java.io :as io]
            [clojure.pprint :as pprint]))

(defonce store (memory/memory-store))

(defn private-page [request]
  {:status  200
   :headers {"Content-Type" "text/plain"}
   :body    (with-out-str (pprint/pprint (:identity request)))})

(defn get-settings []
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
   :onelogin.saml2.sp.single_logout_service.url      "http://localhost:3000/confirm-logout"
   :onelogin.saml2.sp.assertion_consumer_service.url "http://localhost:3000/callback"
   :onelogin.saml2.sp.entityid                       "http://localhost:3000"
   :onelogin.saml2.sp.x509cert                       (slurp (io/resource "sp-public-cert.pem"))
   :onelogin.saml2.sp.privatekey                     (slurp (io/resource "sp-private-key.pem"))
   :onelogin.saml2.idp.x509cert                      (slurp (io/resource "idp-public-cert.pem"))
   :onelogin.saml2.idp.single_sign_on_service.url    "http://localhost:7000/saml/sso"
   :onelogin.saml2.idp.entityid                      "urn:example:idp"})


(defn login-handler [request]
  (let [handler (bssp/authn-handler (get-settings))]
    (handler request)))

(defn callback-handler [request]
  (let [handler (bssp/acs-handler identity (get-settings))]
    (handler request)))

(defn metadata-handler [request]
  (let [handler (bssp/metadata-handler (get-settings))]
    (handler request)))

(defn wrap-session-authentication [handler]
  (letfn [(unauthorized [request data]
            (-> (str "/login?next="
                     (codec/url-encode
                       (if-not (strings/blank? (:query-string request))
                         (str (:uri request) (str "?" (:query-string request)))
                         (:uri request))))
                (response/redirect)))]
    (let [backend (bb/session {:unauthorized-handler unauthorized})]
      (-> (fn [request]
            (if (buddy/authenticated? request)
              (handler request)
              (buddy/throw-unauthorized)))
          (bmw/wrap-authorization backend)
          (bmw/wrap-authentication backend)))))

(defn wrap-handle-unauthenticated [handler]
  (fn [request]
    (try (handler request)
         (catch Exception e
           (if (= (ex-message e) "Unauthorized.")
             (response/redirect "/login")
             (throw e))))))

(defn wrap-default-middleware [handler]
  (let [options (-> defaults/site-defaults
                    (assoc-in [:security :anti-forgery] false)
                    (assoc-in [:session :store] store))]
    (defaults/wrap-defaults handler options)))

(defn get-confirm-logout-settings []
  (-> (get-settings)
      (assoc :onelogin.saml2.security.want_messages_signed false)))


(def routes
  {"/"
   (-> private-page
       wrap-session-authentication
       wrap-handle-unauthenticated
       wrap-default-middleware)

   "/login"
   (-> login-handler
       wrap-handle-unauthenticated
       wrap-default-middleware)

   "/initiate-logout"
   (-> (bssp/initiate-logout-handler (get-settings))
       wrap-default-middleware)

   "/confirm-logout"
   (-> (bssp/perform-logout-handler (get-confirm-logout-settings))
       wrap-default-middleware)

   "/callback"
   (-> callback-handler
       wrap-handle-unauthenticated
       wrap-default-middleware)

   "/metadata"
   (-> metadata-handler
       wrap-handle-unauthenticated
       wrap-default-middleware)})


(defn application [request]
  ((or (routes (:uri request))
       (fn [_] {:status 404 :body "Not found."}))
   request))

(defn create-server []
  (let [opts {:port 3000 :join? false}]
    (jetty/run-jetty (fn [req] (#'application req)) opts)))