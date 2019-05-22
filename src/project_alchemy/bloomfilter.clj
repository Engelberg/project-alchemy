(ns ^{:author "Mark Engelberg",
      :doc "A Clojure port of chapter 9 of Programming Bitcoin"}
    project-alchemy.bloomfilter
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

(def BIP37_CONSTANT 0xfba4c795)

(defrecord BloomFilter [size bit-field function-count tweak])
(defnc ->BloomFilter [size function-count tweak]
  (BloomFilter. size (vec (repeat (* size 8) 0)) function-count tweak))

(defnc add-to-filter [{:keys [function-count] :as filter} item]
  (reduce (fn update-bit [{:keys [size bit-field tweak] :as filter} i]
            (let [seed (unchecked-int (+ tweak (* i BIP37_CONSTANT)))
                  murmur-hash (helper/murmur3 item seed)
                  new-bit-field (assoc bit-field (mod murmur-hash (* size 8)) 1)]
              (BloomFilter. size new-bit-field function-count tweak)))
          filter (range function-count)))
                  
(defn filterload "Returns a filterload message to send over network"
  ([filter] (filterload filter 1))
  ([{:keys [size bit-field function-count tweak]} flag]
   {:command-name "filterload",
    :payload (byte-array (concat (encode-varint size)
                                 (helper/bits->bytes bit-field)
                                 (le-num->bytes 4 function-count)
                                 (le-num->bytes 4 tweak)
                                 (le-num->bytes 1 flag)))}))
