(defproject buddy-saml-service-provider "0.1.0-SNAPSHOT"

  :dependencies
  [[org.clojure/clojure "1.10.1"]
   [com.onelogin/java-saml "2.5.0"]
   [javax.servlet/javax.servlet-api "3.1.0"]
   [buddy/buddy-auth "2.2.0"]]

  :profiles
  {:test {:dependencies   [[ring "1.8.0"]
                           [ring/ring-defaults "0.3.2"]
                           [org.slf4j/slf4j-simple "1.7.30"]]
          :resource-paths ["testfiles"]}}

  :repl-options
  {:init-ns buddy-saml-service-provider.core})
