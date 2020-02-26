(defproject org.clojars.rutledgepaulv/saml-service-provider "0.1.1-SNAPSHOT"

  :description
  "Middleware for implementing a saml service provider."

  :url
  "https://github.com/rutledgepaulv/saml-service-provider"

  :license
  {:name "MIT" :url "http://opensource.org/licenses/MIT" :year 2020}

  :dependencies
  [[org.clojure/clojure "1.10.1"]
   [com.onelogin/java-saml "2.5.0"]
   [javax.servlet/javax.servlet-api "3.1.0"]
   [ring/ring-core "1.8.0"]]

  :profiles
  {:test
   {:dependencies
    [[ring "1.8.0"]
     [ring/ring-defaults "0.3.2"]
     [org.slf4j/slf4j-simple "1.7.30"]]
    :resource-paths
    ["testfiles"]}}

  :deploy-repositories
  [["releases" :clojars]
   ["snapshots" :clojars]]

  :repl-options
  {:init-ns saml-service-provider.core})
