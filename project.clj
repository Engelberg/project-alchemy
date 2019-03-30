(defproject project-alchemy "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [better-cond "2.0.2"]                 
                 [org.clojure/math.numeric-tower "0.0.4"]
                 [org.clojure/core.memoize "0.7.1"]
                 [buddy/buddy-core "1.4.0"]
                 [byte-streams "0.2.4"]
                 [funcool/octet "1.1.1"]
                 [bytebuffer "0.2.0"]
                 [gloss "0.2.6"]]
  :repl-options {:init-ns project-alchemy.core})
