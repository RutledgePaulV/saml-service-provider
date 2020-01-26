(ns buddy-saml-service-provider.core
  (:require [clojure.walk :as walk]
            [clojure.java.io :as io]
            [buddy.auth :as auth]
            [clojure.edn :as edn])
  (:import (com.onelogin.saml2.settings SettingsBuilder Saml2Settings)
           (javax.servlet.http HttpServletRequest HttpServletResponse)
           (com.onelogin.saml2 Auth)
           (java.util UUID)))

(defn string-keys [m]
  (walk/stringify-keys m))

(defn keyword-keys [m]
  (walk/keywordize-keys m))

(def DEFAULT_SETTINGS
  (-> (io/resource "saml-default-settings.edn")
      (io/input-stream)
      (slurp)
      (edn/read-string)
      (string-keys)))

(defn ^Saml2Settings map->settings [m]
  (->> (merge DEFAULT_SETTINGS (string-keys m))
       (.fromValues (SettingsBuilder.))
       (.build)))

(defn- request->param-map [request]
  (->>
    (merge (:params request)
           (:form-params request)
           (:query-params request))
    (string-keys)
    (reduce-kv (fn [m k v] (assoc m k (if (coll? v) (into-array String v) v))) {})))

(defn- response->map [^Auth auth]
  (merge (keyword-keys (.getAttributes auth)) {:nameId (.getNameId auth)}))

(defn- request->url [request]
  (let [proto (name (:protocol request))
        ports {"http" 80 "https" 443}]
    (doto (StringBuffer.)
      (.append proto)
      (.append "://")
      (.append (:server-name request))
      (.append (if (= (get ports proto) (:port request))
                 ""
                 (str ":" (:port request))))
      (.append (:uri request)))))

(defn- shim-async [handler]
  (fn
    ([request] (handler request))
    ([req resp raise]
     (try
       (resp (handler req))
       (catch Exception e
         (raise e))))))


(defn ^HttpServletRequest ring-request->http-request
  "Implements a subset of the http servlet request interface
   to satisfy the requirements of onelogin/java-saml"
  [request]
  (proxy [HttpServletRequest] []

    (getParameterMap []
      (request->param-map request))

    (getRequestURL []
      (request->url request))

    (getQueryString []
      (request :query-string))

    (getRequestURI []
      (request :uri))

    (isSecure []
      (= (name (:protocol request)) "https"))))

(defn authn-handler [settings]
  (let [saml-settings (map->settings settings)]
    (shim-async
      (fn [request]
        (let [http-servlet-req (ring-request->http-request request)
              redirect         (promise)
              http-servlet-res (proxy [HttpServletResponse] []
                                 (sendRedirect [location]
                                   (deliver redirect location)))
              auth             (Auth. saml-settings http-servlet-req http-servlet-res)
              relay-state      (UUID/randomUUID)
              next             (get-in request [:query-params :next])
              redirect         (.login auth relay-state false false false true nil)]
          {:status  302
           :headers {"Location" redirect}
           :session (-> (:session request)
                        (assoc ::next next)
                        (update ::relay (fnil conj #{}) relay-state))
           :body    ""})))))

(defn validate-relay-state [request]
  (let [relay-state (or (get-in request [:query-params :RelayState])
                        (get-in request [:query-params "RelayState"]))]
    (contains? (get-in request [:session ::relay] #{}) relay-state)))

(defn acs-handler [auth-fn settings]
  (let [saml-settings (map->settings settings)]
    (shim-async
      (fn [request]
        (let [http-servlet-req (ring-request->http-request request)
              http-servlet-res (proxy [HttpServletResponse] [])
              auth             (Auth. saml-settings http-servlet-req http-servlet-res)
              _                (.processResponse auth)
              session          (get request :session)]
          (if (and (empty (.getErrors auth))
                   (.isAuthenticated auth)
                   (validate-relay-state request))
            (let [auth-context (auth-fn (response->map auth))]
              {:status  302
               :headers {"Location" (get session ::next)}
               :session (-> session
                            (dissoc ::next ::relay)
                            (assoc :identity auth-context)
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


(defn metadata-response [settings]
  (let [saml-settings (map->settings settings)
        xml           (.getSPMetadata saml-settings)]
    (shim-async
      (fn [request] {:status 200 :headers {"Content-Type" "application/xml"} :body xml}))))



