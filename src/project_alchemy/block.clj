(ns ^{:author "Mark Engelberg",
      :doc "A Clojure port of chapter 9 of Programming Bitcoin"}
    project-alchemy.block
  (:refer-clojure :exclude [cond])
  (:require [better-cond.core :refer [cond defnc defnc-]]
            [project-alchemy.helper :refer [read-bytes read-varint encode-varint
                                            le-bytes->num le-num->bytes hash256]
             :as helper]
            [buddy.core.codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [clojure.java.io :as io]
            [medley.core :as medley]
            [clojure.math.numeric-tower :as m])
  (:import java.io.InputStream))

(defrecord Block [version prev-block merkle-root timestamp bits nonce])

(defnc parse-block [^InputStream stream]
  :let [version (le-bytes->num (read-bytes stream 4)),
        prev-block (byte-array (reverse (read-bytes stream 32))),
        merkle-root (byte-array (reverse (read-bytes stream 32))),
        timestamp (le-bytes->num (read-bytes stream 4)),
        bits (read-bytes stream 4),
        nonce (read-bytes stream 4)]
  (->Block version prev-block merkle-root timestamp bits nonce))

(defn serialize-block ^bytes
  [{:keys [version prev-block merkle-root timestamp bits nonce]}]
  (byte-array (concat (le-num->bytes 4 version) (reverse prev-block)
                      (reverse merkle-root) (le-num->bytes 4 timestamp)
                      bits nonce)))

(defn hash-block [block]
  (byte-array (reverse (hash256 (serialize-block block)))))

(defn bip9? [{^BigInteger v :version}]
  (= 1 (.shiftRight v 29)))

(defn bip91? [{^BigInteger v :version}]
  (= 1 (.and BigInteger/ONE (.shiftRight v 4))))

(defn bip141? [{^BigInteger v :version}]
  (= 1 (.and BigInteger/ONE (.shiftRight v 1))))

(defn target [{:keys [bits]}]
  (helper/bits->target bits))

(defn difficulty [block]
  (/ (*' 0xffff (m/expt 256 (- 0x1d 3))) (target block)))

(defn valid-pow? [block]
  (< (le-bytes->num (hash256 (serialize-block block))) (target block)))
