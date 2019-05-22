(ns ^{:author "Mark Engelberg",
      :doc "A Clojure port of chapter 9 of Programming Bitcoin"}
    project-alchemy.merkle-block
  (:refer-clojure :exclude [cond])
  (:require [better-cond.core :refer [cond defnc defnc-]]
            [project-alchemy.helper :refer [read-bytes read-varint encode-varint
                                            le-bytes->num le-num->bytes hash256]
             :as helper]
            [buddy.core.codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [clojure.java.io :as io]
            [medley.core :as medley]
            [clojure.math.numeric-tower :as m]
            [clojure.zip :as z])
  (:import java.io.InputStream))

;; Using a totally different representation than book to use zippers

(defn make-empty-tree [total]
  (loop [tree (repeat total nil)]
    (cond
      (= (count tree) 2) tree
      (recur (mapv vec (partition-all 2 tree))))))

(defnc reduce-tree [tree bits hashes]
  :let [end (loop [prev nil, loc (z/vector-zip tree), bits bits, hashes hashes]
              (cond
                (z/end? loc) prev
                (or (not (z/branch? loc)) (= (first bits) 0))
                (let [r (z/replace loc (first hashes))]
                  (recur r (z/next r) (next bits) (next hashes))),
                (recur loc (z/next loc) (next bits) hashes)))]
  (loop [loc end, after nil]
    (cond
      (nil? loc) (z/root after)
      (not (z/branch? loc)) (recur (z/prev loc) loc)
      :let [[left right :as children] (z/children loc)]
      (= (count children) 1)
      (let [r (z/replace loc (helper/merkle-parent left left))]
        (recur (z/prev r) r))
      :else (let [r (z/replace loc (helper/merkle-parent left right))]
              (recur (z/prev r) r)))))

(defrecord MerkleBlock [version prev-block merkle-root timestamp bits nonce total hashes flags])

(defnc parse-merkle-block [^InputStream s]
  :let [version (le-bytes->num (read-bytes s 4)),
        prev-block (byte-array (reverse (read-bytes s 32)))
        merkle-root (byte-array (reverse (read-bytes s 32)))
        timestamp (le-bytes->num (read-bytes s 4)),
        bits (read-bytes s 4)
        nonce (read-bytes s 4)
        total (le-bytes->num (read-bytes s 4))
        num-hashes (read-varint s)
        hashes (vec (for [i (range num-hashes)]
                      (byte-array (reverse (read-bytes s 32)))))
        flags (read-bytes s (read-varint s))]
  (->MerkleBlock version prev-block merkle-root timestamp bits nonce total hashes flags))

(defnc valid-merkle-block? [{:keys [total hashes flags merkle-root]}]
  :let [flag-bits (helper/bytes->bits flags),
        hashes (into [] (map #(byte-array (reverse %))) hashes),
        tree (make-empty-tree total)
        computed-root (reduce-tree tree flag-bits hashes)]
  (bytes/equals? (byte-array (reverse computed-root)) merkle-root))


