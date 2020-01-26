(ns buddy-saml-service-provider.core
  (:require [clojure.walk :as walk]
            [clojure.java.io :as io]
            [buddy.auth :as auth]
            [clojure.edn :as edn])
  (:import (com.onelogin.saml2.settings SettingsBuilder Saml2Settings)
           (javax.servlet.http HttpServletRequest HttpServletResponse)
           (com.onelogin.saml2 Auth)
           (java.util UUID)))

(defn- string-keys [m]
  (walk/stringify-keys m))

(defn- keyword-keys [m]
  (walk/keywordize-keys m))

(def ^:private DEFAULT_SETTINGS
  (delay (-> (io/resource "saml-default-settings.edn")
             (io/input-stream)
             (slurp)
             (edn/read-string)
             (string-keys))))

(defn- ^Saml2Settings map->settings [m]
  (->> (merge (force DEFAULT_SETTINGS) (string-keys m))
       (.fromValues (SettingsBuilder.))
       (.build)))

(defn- request->param-map [request]
  (->>
    (merge (:params request) (:form-params request) (:query-params request))
    (string-keys)
    (reduce-kv (fn [m k v]
                 (let [vs (if (coll? v)
                            (into-array String v)
                            (into-array String [v]))]
                   (assoc m k vs))) {})))

(defn- response->map [^Auth auth]
  (merge (keyword-keys (into {} (.getAttributes auth)))
         {:nameId                (.getNameId auth)
          :nameIdFormat          (.getNameIdFormat auth)
          :nameIdNameQualifier   (.getNameIdNameQualifier auth)
          :nameIdSPNameQualifier (.getNameIdSPNameQualifier auth)
          :sessionIndex          (.getSessionIndex auth)}))

(defn- request->url [request]
  (let [proto (name (:scheme request))
        port  (:server-port request)
        ports {"http" 80 "https" 443}]
    (doto (StringBuffer.)
      (.append proto)
      (.append "://")
      (.append (:server-name request))
      (.append (if (= (get ports proto) port) "" (str ":" port)))
      (.append (:uri request)))))

(defn- shim-async [handler]
  (fn async-ring-handler-shim
    ([request] (handler request))
    ([req resp raise]
     (try
       (resp (handler req))
       (catch Exception e
         (raise e))))))


(defn- ^HttpServletRequest ring-request->http-request
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

(defn- get-relay-state [request]
  (or (get-in request [:form-params :RelayState])
      (get-in request [:form-params "RelayState"])
      (get-in request [:query-params :RelayState])
      (get-in request [:query-params "RelayState"])
      (get-in request [:params :RelayState])
      (get-in request [:params "RelayState"])))

(defn- validate-relay-state [request]
  (let [relay-state (get-relay-state request)
        states      (get-in request [:session ::relay] #{})]
    (contains? states relay-state)))

(defn authn-handler [settings]
  (let [saml-settings (map->settings settings)]
    (shim-async
      (fn [request]
        (let [http-servlet-req (ring-request->http-request request)
              http-servlet-res (proxy [HttpServletResponse] [])
              auth             (Auth. saml-settings http-servlet-req http-servlet-res)
              relay-state      (str (UUID/randomUUID))
              next             (get-in request [:query-params :next])
              redirect         (.login auth relay-state false false false true nil)]
          {:status  302
           :headers {"Location" redirect}
           :session (-> (:session request)
                        (assoc ::next (or next "/"))
                        (update ::relay (fnil conj #{}) relay-state))
           :body    ""})))))

(defn acs-handler [auth-fn settings]
  (let [saml-settings (map->settings settings)]
    (shim-async
      (fn [request]
        (let [http-servlet-req (ring-request->http-request request)
              http-servlet-res (proxy [HttpServletResponse] [])
              auth             (Auth. saml-settings http-servlet-req http-servlet-res)
              _                (.processResponse auth)
              session          (get request :session)
              valid            (and (empty? (.getErrors auth))
                                    (.isAuthenticated auth)
                                    (validate-relay-state request))]
          (if (identity valid)
            (let [auth-context (response->map auth)
                  ident        (auth-fn auth-context)]
              {:status  302
               :headers {"Location" (get session ::next)}
               :session (-> session
                            (dissoc ::next)
                            (update ::relay disj (get-relay-state request))
                            (assoc :identity ident)
                            (assoc ::auth-context auth-context)
                            (vary-meta assoc :recreate true))
               :body    ""})
            (auth/throw-unauthorized
              (cond-> {}
                (not-empty (.getErrors auth))
                (assoc :saml-errors (vec (.getErrors auth)))
                (not (.isAuthenticated auth))
                (assoc :message "User was not authenticated.")
                (not (validate-relay-state request))
                (assoc :message "Provided relay state wasn't in the set of expected relay states for the user's session.")))))))))


(defn initiate-logout-handler [settings]
  (let [saml-settings (map->settings settings)]
    (shim-async
      (fn [request]
        (if-some [{:keys [nameId sessionIndex nameIdFormat nameIdNameQualifier nameIdSPNameQualifier]}
                  (get-in request [:session ::auth-context])]
          (let [http-servlet-req (ring-request->http-request request)
                http-servlet-res (proxy [HttpServletResponse] [])
                auth             (Auth. saml-settings http-servlet-req http-servlet-res)
                relay-state      (str (UUID/randomUUID))
                next             (get-in request [:query-params :next])
                redirect         (.logout auth relay-state nameId sessionIndex true nameIdFormat nameIdNameQualifier nameIdSPNameQualifier)]
            {:status  302
             :headers {"Location" redirect}
             :session (-> (:session request)
                          (assoc ::next (or next "/"))
                          (update ::relay (fnil conj #{}) relay-state))
             :body    ""})
          (auth/throw-unauthorized
            {:message "You cannot logout because you're not logged in using this mechanism."}))))))


(defn perform-logout-handler [settings]
  (let [saml-settings (map->settings settings)]
    (shim-async
      (fn [request]
        (let [http-servlet-req (ring-request->http-request request)
              redirect-promise (promise)
              http-servlet-res (proxy [HttpServletResponse] []
                                 (sendRedirect [location]
                                   (deliver redirect-promise location)))
              auth             (Auth. saml-settings http-servlet-req http-servlet-res)
              _                (.processSLO auth true nil)
              session          (:session request)]
          (if (empty? (.getErrors auth))
            (if (realized? redirect-promise)
              {:status  302
               :headers {"Location" @redirect-promise}
               :session nil
               :body    ""}
              {:status  302
               :headers {"Location" (get session ::next)}
               :session nil
               :body    ""})
            (auth/throw-unauthorized
              {:message "Errors were encountered while processing the logout request."
               :errors  (.getErrors auth)})))))))


(defn metadata-handler [settings]
  (let [saml-settings (map->settings settings)
        xml           (.getSPMetadata saml-settings)]
    (shim-async (fn [_] {:status 200 :headers {"Content-Type" "application/xml"} :body xml}))))



