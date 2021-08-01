(ns saml-service-provider.core
  (:require [clojure.string :as strings]
            [saml-service-provider.utils :as utils]
            [ring.util.codec :as codec])
  (:import (javax.servlet.http HttpServletResponse)
           (com.onelogin.saml2 Auth)
           (java.util UUID)))


(defn authn-handler [settings]
  (utils/shim-async
    (fn [request]
      (let [base-url         (utils/request->base-url request)
            saml-settings    (utils/settings-for-domain settings base-url)
            http-servlet-req (utils/ring-request->http-request request)
            http-servlet-res (proxy [HttpServletResponse] [])
            auth             (Auth. saml-settings http-servlet-req http-servlet-res)
            relay-state      (str (UUID/randomUUID))
            next             (utils/get-next-url request)
            redirect         (.login auth relay-state false false false true nil)]
        {:status  302
         :headers {"Location" redirect}
         :session (-> (:session request {})
                      (assoc ::next next)
                      (update ::relay (fnil conj #{}) relay-state))
         :body    ""}))))

(defn acs-handler [auth-fn settings]
  (utils/shim-async
    (fn [request]
      (let [base-url         (utils/request->base-url request)
            saml-settings    (utils/settings-for-domain settings base-url)
            http-servlet-req (utils/ring-request->http-request request)
            http-servlet-res (proxy [HttpServletResponse] [])
            auth             (doto (Auth. saml-settings http-servlet-req http-servlet-res)
                               (.processResponse))
            session          (get request :session {})
            relay-state      (utils/get-relay-state request)
            valid-relay      (contains? (get-in request [:session ::relay] #{}) relay-state)
            valid-callback   (and (empty? (.getErrors auth)) (.isAuthenticated auth) valid-relay)]
        (if valid-callback
          (let [auth-context (utils/response->map auth)
                ident        (auth-fn auth-context)]
            {:status  302
             :headers {"Location" (utils/get-next-url request)}
             :session (-> session
                          (dissoc ::next)
                          (update ::relay disj relay-state)
                          (assoc ::identity ident)
                          (assoc ::auth-context auth-context)
                          (vary-meta assoc :recreate true))
             :body    ""})
          (utils/throw-exception "Encountered error in acs handler."
            (cond-> {}
              (not-empty (.getErrors auth))
              (assoc :saml-errors (vec (.getErrors auth)))
              (not (.isAuthenticated auth))
              (assoc :message "User was not properly authenticated by IDP.")
              (not valid-relay)
              (assoc :message "Provided relay state wasn't in the set of expected relay states for the user's session."))))))))


(defn initiate-logout-handler [settings]
  (utils/shim-async
    (fn [request]
      (if-some [{:keys [nameId sessionIndex nameIdFormat nameIdNameQualifier nameIdSPNameQualifier]}
                (get-in request [:session ::auth-context])]
        (let [base-url         (utils/request->base-url request)
              saml-settings    (utils/settings-for-domain settings base-url)
              http-servlet-req (utils/ring-request->http-request request)
              http-servlet-res (proxy [HttpServletResponse] [])
              auth             (Auth. saml-settings http-servlet-req http-servlet-res)
              relay-state      (str (UUID/randomUUID))
              next             (utils/get-next-url request)
              redirect         (.logout auth relay-state nameId sessionIndex true nameIdFormat nameIdNameQualifier nameIdSPNameQualifier)]
          {:status  302
           :headers {"Location" redirect}
           :session (-> (:session request)
                        (assoc ::next next)
                        (update ::relay (fnil conj #{}) relay-state))
           :body    ""})
        (utils/throw-exception "You cannot logout because you're not logged in.")))))


(defn perform-logout-handler [settings]
  (utils/shim-async
    (fn [request]
      (let [base-url         (utils/request->base-url request)
            saml-settings    (utils/settings-for-domain settings base-url)
            http-servlet-req (utils/ring-request->http-request request)
            redirect-promise (promise)
            http-servlet-res (proxy [HttpServletResponse] []
                               (sendRedirect [location]
                                 (deliver redirect-promise location)))
            auth             (doto (Auth. saml-settings http-servlet-req http-servlet-res)
                               (.processSLO true nil))
            session          (:session request)]
        (if (empty? (.getErrors auth))
          ; idp initiated logout
          (if (realized? redirect-promise)
            {:status  302
             :headers {"Location" @redirect-promise}
             :session nil
             :body    ""}
            ; service provider initiated logout
            {:status  302
             :headers {"Location" (or (get session ::next) "/")}
             :session nil
             :body    ""})
          (utils/throw-exception "Errors were encountered while processing the logout request." {:errors (.getErrors auth)}))))))


(defn metadata-handler [settings]
  (let [metadata-fn
        (memoize
          (fn [base-url]
            (let [saml-settings (utils/settings-for-domain settings base-url)]
              (.getSPMetadata saml-settings))))]
    (utils/shim-async
      (fn [request]
        {:status  200
         :headers {"Content-Type" "application/xml"}
         :body    (metadata-fn (utils/request->base-url request))}))))


(defn wrap-require-authentication [handler login-uri]
  (utils/shim-async
    (fn [request]
      (let [identity (utils/get-identity request)
            expired  (utils/session-expired? request)]
        (if (and (some? identity) (not expired))
          (handler (assoc request ::identity identity))
          (let [after-authenticate
                (codec/url-encode
                  (if-not (strings/blank? (:query-string request))
                    (str (:uri request) (str "?" (:query-string request)))
                    (:uri request)))
                redirect
                (cond-> login-uri
                  (not= "/" after-authenticate)
                  (str "?next=" after-authenticate))]
            (cond-> {:status 302 :headers {"Location" redirect} :body ""}
              expired (assoc :session nil))))))))


(defn finalize-settings
  [{:keys [endpoints
           idp-metadata-url
           onelogin-settings]
    :or   {endpoints {:login           "/saml/login"
                      :authn           "/saml/login"
                      :acs             "/saml/acs"
                      :metadata        "/saml/metadata"
                      :initiate-logout "/saml/initiate-logout"
                      :confirm-logout  "/saml/confirm-logout"}}}]
  {:endpoints         endpoints
   :idp-metadata-url  idp-metadata-url
   :onelogin-settings onelogin-settings})


(defn wrap-saml-authentication
  "Wraps a ring handler with required SAML authentication.

   auth-fn            - an optional function to interpret the saml response data into an authenticated identity.
                        defaults to clojure.core/identity
   endpoints          - a map of uris for each of the saml endpoints being implemented by this middleware.
   idp-metadata-url   - an optional url from which to access the idp metadata. if provided metadata will be accessed,
                        parsed, and made part of the onelogin-settings for the middleware in order to configure the
                        provider settings. at this time no attempt is made to periodically refresh the idp configuration.
   onelogin-settings  - a map of onelogin settings used to configure the service provider (certificates, contact info, etc)
   "
  [handler {:keys [auth-fn] :or {auth-fn identity} :as settings}]
  (let [settings        (finalize-settings settings)
        logout-settings (assoc-in settings [:onelogin-settings :onelogin.saml2.security.want_messages_signed] false)
        dispatch-table  {[:get (get-in settings [:endpoints :authn])]           (authn-handler settings)
                         [:post (get-in settings [:endpoints :acs])]            (acs-handler auth-fn settings)
                         [:get (get-in settings [:endpoints :metadata])]        (metadata-handler settings)
                         [:get (get-in settings [:endpoints :initiate-logout])] (initiate-logout-handler settings)
                         [:post (get settings [:endpoints :confirm-logout])]    (perform-logout-handler logout-settings)}
        wrapped         (wrap-require-authentication handler (get-in settings [:endpoints :login]))]
    (utils/disable-csrf-for-endpoints!
      #{[:post (get-in settings [:endpoints :acs])]
        [:post (get settings [:endpoints :confirm-logout])]})
    (fn saml-authentication-handler
      ([request]
       (if-some [lib-route (get dispatch-table [(:request-method request) (:uri request)])]
         (lib-route request)
         (wrapped request)))
      ([request respond raise]
       (if-some [lib-route (get dispatch-table [(:request-method request) (:uri request)])]
         (lib-route request respond raise)
         (wrapped request respond raise))))))
