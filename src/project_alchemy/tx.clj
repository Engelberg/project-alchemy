(ns ^{:author "Mark Engelberg",
      :doc "A Clojure port of chapter 5 of Programming Bitcoin"}
    project-alchemy.tx
  (:refer-clojure :exclude [cond hash])
  (:require [better-cond.core :refer [cond defnc defnc-]]
            [project-alchemy.helper :refer [read-bytes read-varint encode-varint le-bytes->num le-num->bytes bytes->num hash256] :as helper]
            [project-alchemy.script :as script]
            [project-alchemy.ecc :as ecc]
            [buddy.core.codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [clojure.java.io :as io]
            [medley.core :as medley]
            [clojure.core.memoize :as memoize])
  (:import java.io.InputStream))

(declare id parse-tx)
(def SIGHASH_ALL 1)
(def SIGHASH_NONE 2)
(def SIGHASH_SINGLE 3)

(defrecord Tx [version tx-ins tx-outs locktime testnet?])
(defrecord TxIn [prev-tx prev-index script-sig sequence])
(defrecord TxOut [amount script-pubkey])

;; Fetching txs, needed to look up info about previous txs

(defn get-url [tx-id testnet?]
  (if testnet?
    (format "http://testnet.programmingbitcoin.com/tx/%s.hex" tx-id)
    ;; mainnet.programmingbitcoin.com appears to be down, so we use blockchain.info
    (format "https://blockchain.info/rawtx/%s?format=hex" tx-id)))

(defnc fetch-tx [tx-id testnet?]
  :let [url (get-url tx-id testnet?)
        response (slurp url)
        raw (hex->bytes (clojure.string/trim response))
        tx (parse-tx (io/input-stream raw) testnet?)]
  ;; :do (println (id tx) tx-id)
  :do (assert (= (id tx) tx-id)
              (format "IDs don't match %s %s" (id tx) tx-id))
  ;; Currently assumes it is NOT a segwit transaction
  ;; Book has hack to work around segwit txs, but seems better to wait
  ;; and code it correctly
  tx)
;;(def fetch-tx (memoize/fifo fetch-tx))

;; parsing and serializing

(defnc parse-tx-in [^InputStream stream]
  :let [prev-tx (byte-array (reverse (read-bytes stream 32)))
        prev-index (le-bytes->num (read-bytes stream 4))
        script-sig (script/parse-script stream) 
        sequence (le-bytes->num (read-bytes stream 4))]
  (->TxIn prev-tx prev-index script-sig sequence))

(defn serialize-tx-in ^bytes [{:keys [prev-tx prev-index script-sig sequence]}]
  (byte-array (concat (reverse prev-tx)
                      (le-num->bytes 4 prev-index)
                      (script/serialize-script script-sig)
                      (le-num->bytes 4 sequence))))

(defn fetch-tx-in [{:keys [prev-tx]} testnet?]
  (fetch-tx (bytes->hex prev-tx) testnet?))

(defnc amount-tx-in [{:keys [prev-index] :as tx-in} testnet?]
  :let [{:keys [tx-outs]} (fetch-tx-in tx-in testnet?)]
  (:amount (nth tx-outs prev-index)))

(defnc script-pubkey-tx-in [{:keys [prev-index] :as tx-in} testnet?]
  :let [{:keys [tx-outs]} (fetch-tx-in tx-in testnet?)]
  (:script-pubkey (nth tx-outs prev-index)))

(defnc parse-tx-out [^InputStream stream]
  :let [amount (le-bytes->num (read-bytes stream 8))
        script-pubkey (script/parse-script stream)] 
  (->TxOut amount script-pubkey))

(defn serialize-tx-out [{:keys [amount script-pubkey]}]
  (bytes/concat (le-num->bytes 8 amount)
                (script/serialize-script script-pubkey)))

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
  (byte-array
   (concat (le-num->bytes 4 version)
           (encode-varint (count tx-ins))
           (apply concat (for [tx-in tx-ins] (serialize-tx-in tx-in)))
           (encode-varint (count tx-outs))
           (apply concat (for [tx-out tx-outs] (serialize-tx-out tx-out)))
           (le-num->bytes 4 locktime))))

(defn tx-hash [tx]
  (byte-array (reverse (hash256 (serialize-tx tx)))))

(defn id [tx]
  (bytes->hex (tx-hash tx)))

;; Verifying tx

(defnc fee [{:keys [tx-ins tx-outs testnet?]}]
  :let [value-ins (apply + (for [tx-in tx-ins] (amount-tx-in tx-in testnet?)))
        value-outs (apply + (for [tx-out tx-outs] (:amount tx-out)))]
  (-' value-ins value-outs))

(defnc sig-hash
  ([tx input-index] (sig-hash tx input-index nil))
  ([{:keys [version tx-ins tx-outs locktime testnet?]} input-index redeem-script]
   :let [bytes
         (byte-array
          (concat (le-num->bytes 4 version)
                  (encode-varint (count tx-ins))
                  (apply concat
                         (for [[i tx-in] (medley/indexed tx-ins)
                               :let [{:keys [prev-tx prev-index script-pubkey
                                             sequence]} tx-in]]
                           (serialize-tx-in
                            (->TxIn prev-tx prev-index
                                    (when (= i input-index)
                                      (if redeem-script redeem-script
                                          (script-pubkey-tx-in tx-in testnet?)))
                                    sequence))))
                  (encode-varint (count tx-outs))
                  (apply concat (for [tx-out tx-outs] (serialize-tx-out tx-out)))
                  (le-num->bytes 4 locktime)
                  (le-num->bytes 4 SIGHASH_ALL)))]
   (bytes->num (hash256 bytes))))
  
(defnc verify-tx-in [{:keys [tx-ins testnet?] :as tx} input-index]
  :let [{:keys [script-sig] :as tx-in} (nth tx-ins input-index),
        script-pubkey (script-pubkey-tx-in tx-in testnet?)
        redeem-script (when (script/p2sh-script? script-pubkey)
                        (let [cmd (last script-sig),
                              raw-redeem (bytes/concat (encode-varint (count cmd))
                                                       cmd)]
                          (script/parse-script (io/input-stream raw-redeem))))
        z (sig-hash tx input-index redeem-script),
        script (concat (:script-sig tx-in) script-pubkey)]
  (script/evaluate-script script z))

(defnc verify-tx [{:keys [tx-ins] :as tx}]
  (neg? (fee tx)) false
  (every? #(verify-tx-in tx %) (range (count tx-ins))))

(defnc sign-input "Returns signed tx or nil if invalid"
  [tx input-index private-key]
  :let [z (sig-hash tx input-index)
        signature (ecc/sign private-key z)
        der (ecc/der signature)
        sighash-all (helper/num->bytes 1 SIGHASH_ALL)
        full-signature (bytes/concat der sighash-all)
        sec (ecc/sec (:point private-key))
        script-sig [full-signature sec]
        new-tx (assoc-in tx [:tx-ins input-index :script-sig] script-sig)]
  (verify-tx-in new-tx input-index) new-tx
  nil)
        
        
  

