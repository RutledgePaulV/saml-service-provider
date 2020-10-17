(ns saml-service-provider.core-test
  (:require [saml-service-provider.core :as sspc]
            [ring.adapter.jetty :as jetty]
            [ring.middleware.defaults :as defaults]
            [clojure.java.io :as io]
            [clojure.pprint :as pprint])
  (:import (org.eclipse.jetty.server Server)))

(defn private-page [request]
  {:status  200
   :headers {"Content-Type" "text/plain"}
   :body    (with-out-str (pprint/pprint (:saml-service-provider.core/identity request)))})

(def settings
  {:idp-metadata-url
   "http://localhost:7000/metadata"
   :onelogin-settings
   {:onelogin.saml2.sp.x509cert   (slurp (io/resource "sp-public-cert.pem"))
    :onelogin.saml2.sp.privatekey (slurp (io/resource "sp-private-key.pem"))}})

(def application
  (-> private-page
      (sspc/wrap-saml-authentication settings)
      (defaults/wrap-defaults defaults/site-defaults)))

(defn create-server []
  (jetty/run-jetty (fn [req] (#'application req)) {:port 3000 :join? false}))

(defonce server (atom nil))

(defn restart []
  (swap! server
         (fn [old]
           (when (some? old)
             (.stop ^Server old))
           (create-server))))