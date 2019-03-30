(ns ^{:author "Mark Engelberg",
      :doc "A Clojure port of chapter 5 of Programming Bitcoin"}
    project-alchemy.tx
  (:refer-clojure :exclude [cond hash])
  (:require [better-cond.core :refer [cond defnc defnc-]]
            [project-alchemy.helper :refer [read-bytes read-varint encode-varint le-bytes->num le-num->bytes hash256]]
            [project-alchemy.script :as script]
            [buddy.core.codecs :refer :all]
            [clojure.java.io :as io])
  (:import java.io.InputStream))

(defrecord Tx [version tx-ins tx-outs locktime testnet?])
(defrecord TxIn [prev-tx prev-index script-sig sequence])
(defrecord TxOut [amount script-pubkey])

;; Fetching txs, needed to look up info about previous txs

(defn get-url [testnet?]
  (if testnet? "http://testnet.programmingbitcoin.com"
      "http://mainnet.programmingbitcoin.com"))

(defnc fetch-tx [tx-id testnet?]
  :let [url (format "%s/tx/%s.hex" (get-url testnet?) tx-id)
        response (slurp url)
        raw (hex->bytes (clojure.string/trim response))
        tx (parse-tx (io/input-stream raw) testnet?)]
  :do (assert (= (id tx) (:tx-id tx))
              (format "IDs don't match %s %s" (id tx) (:tx-id tx)))
  ;; Currently assumes it is NOT a segwit transaction
  response)

;; parsing and serializing

(defnc parse-tx-in [^InputStream stream]
  :let [prev-tx (le-bytes->num (read-bytes stream 32))
        prev-index (le-bytes->num (read-bytes stream 4))
        script-sig (script/parse-script-sig stream) 
        sequence (le-bytes->num (read-bytes stream 4))]
  (->TxIn prev-tx prev-index script-sig sequence))

(defn serialize-tx-in ^bytes [{:keys [prev-tx prev-index script-sig sequence]}]
  (byte-array (concat (rseq prev-tx)
                      (le-num->bytes 4 prev-index)
                      (script/serialize-script-sig script-sig)
                      (le-num->bytes 4 sequence))))

(defn fetch-tx-in [{:keys [prev-tx]} testnet?]
  (fetch-tx (bytes->hex prev-tx)))

(defnc amount-tx-in [{:keys [prev-index] :as tx-in} testnet?]
  :let [{:keys [tx-outs]} (fetch-tx-in tx-in testnet?)]
  (:amount (nth tx-outs prev-index)))

(defnc script-pubkey-tx-in [{:keys [prev-index] :as tx-in} testnet?]
  :let [{:keys [tx-outs]} (fetch-tx-in tx-in testnet?)]
  (:script-pubkey (nth tx-outs prev-index)))

(defnc parse-tx-out [^InputStream stream]
  :let [amount (le-bytes->num (read-bytes stream 8))
        script-pubkey (script/parse-script-pubkey stream)] 
  (->TxOut amount script-pubkey))

(defn serialize-tx-out [{:keys [amount script-pubkey]}]
  (byte-array (concat (le-num->bytes 8 amount) (script/serialize-script-pubkey script-pubkey))))

(defnc parse-tx [^InputStream stream testnet?]
  :let [version (le-bytes->num (read-bytes stream 4))
        num-tx-ins (read-varint stream)
        tx-ins (vec (for [i (range num-tx-ins)]
                      (parse-tx-in stream)))
        num-tx-outs (read-varint stream)
        tx-outs (vec (for [i (range num-tx-outs)]
                       (parse-tx-out stream)))
        locktime (le-bytes->num (read-bytes stream 4))]
  (->Tx version tx-ins tx-outs locktime testnet?))

(defn serialize-tx ^bytes [{:keys [version tx-ins tx-outs locktime testnet?]}]
  (byte-array (flatten (le-num->bytes 4 version)
                       (encode-varint (count tx-ins))
                       (for [tx-in tx-ins] (serialize-tx-in tx-in))
                       (encode-varint (count tx-outs))
                       (for [tx-out tx-outs] (serialize-tx-out tx-out))
                       (le-num->bytes 4 locktime))))
                                                            
(defn hash [tx]
  (hash256 (byte-array (rseq (serialize-tx tx)))))

(defn id [tx]
  (bytes->hex (tx-hash tx)))

(defnc fee [{:keys [tx-ins tx-outs]} testnet?]
  :let [value-ins (apply + (for [tx-in tx-ins] (amount-tx-in tx-in)))
        value-outs (apply + (for [tx-out tx-outs] (:amount tx-out)))]
  (- value-ins value-outs))
  
  


