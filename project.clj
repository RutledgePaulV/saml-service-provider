(defproject org.clojars.rutledgepaulv/saml-service-provider "0.1.2"

  :description
  "Middleware for implementing a saml service provider."

  :url
  "https://github.com/rutledgepaulv/saml-service-provider"

  :license
  {:name "MIT" :url "http://opensource.org/licenses/MIT" :year 2020}

  :dependencies
  [[org.clojure/clojure "1.10.1"]
   [com.onelogin/java-saml "2.6.0"]
   [javax.servlet/javax.servlet-api "3.1.0"]
   [ring/ring-codec "1.1.2"]]

  :profiles
  {:test
   {:dependencies
    [[ring "1.8.2" :scope "test"]
     [ring/ring-defaults "0.3.2" :scope "test"]
     [org.slf4j/slf4j-simple "1.7.30" :scope "test"]]
    :resource-paths
    ["testfiles"]}}

  :deploy-repositories
  [["releases" :clojars]
   ["snapshots" :clojars]]

  :repl-options
  {:init-ns saml-service-provider.core})
