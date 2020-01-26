(defproject buddy-saml-service-provider "0.1.0-SNAPSHOT"
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [com.onelogin/java-saml "2.5.0"]
                 [javax.servlet/javax.servlet-api "3.1.0"]
                 [buddy/buddy-auth "2.2.0"]]
  :repl-options {:init-ns buddy-saml-service-provider.core})
