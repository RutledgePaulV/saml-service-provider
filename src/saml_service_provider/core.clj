(ns saml-service-provider.core
  (:require [clojure.string :as strings]
            [saml-service-provider.utils :as utils]
            [ring.util.codec :as codec])
  (:import (javax.servlet.http HttpServletResponse)
           (com.onelogin.saml2 Auth)
           (java.util UUID)))


(defn authn-handler [settings]
  (let [saml-settings (utils/map->settings settings)]
    (utils/shim-async
      (fn [request]
        (let [http-servlet-req (utils/ring-request->http-request request)
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
  (let [saml-settings (utils/map->settings settings)]
    (utils/shim-async
      (fn [request]
        (let [http-servlet-req (utils/ring-request->http-request request)
              http-servlet-res (proxy [HttpServletResponse] [])
              auth             (Auth. saml-settings http-servlet-req http-servlet-res)
              _                (.processResponse auth)
              session          (get request :session)
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
                            (assoc :identity ident)
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
                (assoc :message "Provided relay state wasn't in the set of expected relay states for the user's session.")))))))))


(defn initiate-logout-handler [settings]
  (let [saml-settings (utils/map->settings settings)]
    (utils/shim-async
      (fn [request]
        (if-some [{:keys [nameId sessionIndex nameIdFormat nameIdNameQualifier nameIdSPNameQualifier]}
                  (get-in request [:session ::auth-context])]
          (let [http-servlet-req (utils/ring-request->http-request request)
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
          (utils/throw-exception "You cannot logout because you're not logged in."))))))


(defn perform-logout-handler [settings]
  (let [saml-settings (utils/map->settings settings)]
    (utils/shim-async
      (fn [request]
        (let [http-servlet-req (utils/ring-request->http-request request)
              redirect-promise (promise)
              http-servlet-res (proxy [HttpServletResponse] []
                                 (sendRedirect [location]
                                   (deliver redirect-promise location)))
              auth             (Auth. saml-settings http-servlet-req http-servlet-res)
              _                (.processSLO auth true nil)
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
            (utils/throw-exception "Errors were encountered while processing the logout request." {:errors (.getErrors auth)})))))))


(defn metadata-handler [settings]
  (let [saml-settings (utils/map->settings settings)
        xml           (.getSPMetadata saml-settings)]
    (utils/shim-async (fn [_] {:status 200 :headers {"Content-Type" "application/xml"} :body xml}))))

(defn wrap-saml-authentication
  [handler {:keys [auth-fn endpoints onelogin-settings]
            :or   {auth-fn   identity
                   endpoints {:authn           "/saml/login"
                              :acs             "/saml/acs"
                              :metadata        "/saml/metadata"
                              :initiate-logout "/saml/initiate-logout"
                              :confirm-logout  "/saml/confirm-logout"}}}]
  (let [authn-handle           (authn-handler onelogin-settings)
        acs-handle             (acs-handler auth-fn onelogin-settings)
        metadata-handle        (metadata-handler onelogin-settings)
        initiate-logout-handle (initiate-logout-handler onelogin-settings)
        confirm-logout-handler (perform-logout-handler
                                 (assoc onelogin-settings
                                        :onelogin.saml2.security.want_messages_signed
                                   false))]
    (utils/shim-async
      (fn [request]
        (condp = [(:request-method request) (:uri request)]
          [:get (get endpoints :authn)]
          (authn-handle request)
          [:post (get endpoints :acs)]
          (acs-handle request)
          [:get (get endpoints :metadata)]
          (metadata-handle request)
          [:get (get endpoints :initiate-logout)]
          (initiate-logout-handle request)
          [:post (get endpoints :confirm-logout)]
          (confirm-logout-handler request)
          (if-some [identity (utils/get-identity request)]
            (handler (assoc request :identity identity))
            (let [after-authenticate
                  (codec/url-encode
                    (if-not (strings/blank? (:query-string request))
                      (str (:uri request) (str "?" (:query-string request)))
                      (:uri request)))
                  redirect
                  (str (get endpoints :authn) "?next=" after-authenticate)]
              {:status 302 :headers {"Location" redirect} :body ""})))))))

