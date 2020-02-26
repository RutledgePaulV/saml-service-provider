(ns saml-service-provider.utils
  (:require [clojure.edn :as edn]
            [clojure.walk :as walk]
            [clojure.java.io :as io])
  (:import (javax.servlet.http HttpServletRequest)
           (com.onelogin.saml2 Auth)
           (com.onelogin.saml2.settings SettingsBuilder Saml2Settings)))

(defn string-keys [m]
  (walk/stringify-keys m))

(defn keyword-keys [m]
  (walk/keywordize-keys m))

(def DEFAULT_SETTINGS
  (delay (-> (io/resource "saml-default-settings.edn")
             (io/input-stream)
             (slurp)
             (edn/read-string)
             (string-keys))))

(defn ^Saml2Settings map->settings [m]
  (->> (merge (force DEFAULT_SETTINGS) (string-keys m))
       (.fromValues (SettingsBuilder.))
       (.build)))

(defn request->param-map [request]
  (->>
    (merge (:params request) (:form-params request) (:query-params request))
    (string-keys)
    (reduce-kv (fn [m k v]
                 (let [vs (if (coll? v)
                            (into-array String v)
                            (into-array String [v]))]
                   (assoc m k vs))) {})))

(defn response->map [^Auth auth]
  (merge (keyword-keys (into {} (.getAttributes auth)))
         {:nameId                (.getNameId auth)
          :nameIdFormat          (.getNameIdFormat auth)
          :nameIdNameQualifier   (.getNameIdNameQualifier auth)
          :nameIdSPNameQualifier (.getNameIdSPNameQualifier auth)
          :sessionIndex          (.getSessionIndex auth)}))

(defn request->url [request]
  (let [proto (name (:scheme request))
        port  (:server-port request)
        ports {"http" 80 "https" 443}]
    (doto (StringBuffer.)
      (.append proto)
      (.append "://")
      (.append (:server-name request))
      (.append (if (= (get ports proto) port) "" (str ":" port)))
      (.append (:uri request)))))


(defn ^HttpServletRequest ring-request->http-request
  "Implements a subset of the http servlet request interface
   to satisfy the requirements of onelogin/java-saml"
  [request]
  (let [param-map (request->param-map request)]
    (proxy [HttpServletRequest] []

      (getParameterMap []
        param-map)

      (getParameter [parameter]
        (first (get param-map parameter)))

      (getRequestURL []
        (request->url request))

      (getQueryString []
        (request :query-string))

      (getRequestURI []
        (request :uri))

      (isSecure []
        (= (name (:scheme request)) "https")))))

(defn shim-async [handler]
  (fn async-ring-handler-shim
    ([request] (handler request))
    ([req resp raise]
     (try
       (resp (handler req))
       (catch Exception e
         (raise e))))))

(defn get-relay-state [request]
  (or (get-in request [:form-params :RelayState])
      (get-in request [:form-params "RelayState"])
      (get-in request [:query-params :RelayState])
      (get-in request [:query-params "RelayState"])
      (get-in request [:params :RelayState])
      (get-in request [:params "RelayState"])))

(defn get-identity [request]
  (or (get-in request [:identity])
      (get-in request [:session :identity])))

(defn get-next-url [request]
  (or (get-in request [:session ::next]) "/"))

(defn throw-exception
  ([msg]
   (throw-exception msg {}))
  ([msg data]
   (let [extras {:type :saml-service-provider/error :message msg}]
     (throw (ex-info msg (merge data extras))))))