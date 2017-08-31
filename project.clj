(defproject cryptopals "0.1.0-SNAPSHOT"
  :description "the cryptopals crypto challenges"
  :url "http://cryptopals.com"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [commons-codec/commons-codec "1.9"]]
  :global-vars  {*warn-on-reflection* true}
  :main ^:skip-aot cryptopals.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
