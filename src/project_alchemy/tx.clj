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

(defrecord Tx [command-name version tx-ins tx-outs locktime testnet? segwit?])
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
        tx (parse-tx (io/input-stream raw) testnet?)
        computed-id (if (:segwit? tx) (id tx)
                        (bytes->hex (byte-array (reverse (hash256 raw)))))]
  :do (def pt tx)
  :do (def pt-raw raw)
  :do (assert (= computed-id tx-id)
              (format "IDs don't match %s %s" computed-id tx-id))
  tx)
(def fetch-tx (memoize/fifo fetch-tx))

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

(defnc parse-tx-legacy [^InputStream stream testnet?]
  :let [version (le-bytes->num (read-bytes stream 4))
        num-tx-ins (read-varint stream)
        tx-ins (vec (for [i (range num-tx-ins)]
                      (parse-tx-in stream)))
        num-tx-outs (read-varint stream)
        tx-outs (vec (for [i (range num-tx-outs)]
                       (parse-tx-out stream)))
        locktime (le-bytes->num (read-bytes stream 4))]
  (->Tx "tx" version tx-ins tx-outs locktime testnet? false))

;; (defn peek-stream [^InputStream stream]
;;   (.mark stream 10)
;;   (let [b (read-bytes stream 4)]
;;     (.reset stream)
;;     (bytes->hex b)))

(defnc parse-tx-segwit [^InputStream stream testnet?]
  :let [version (le-bytes->num (read-bytes stream 4)),
        marker (vec (read-bytes stream 2))]
  (not= marker [0 1]) (throw (ex-info "Not a segwit transaction" {:marker marker}))
  :let [num-inputs (read-varint stream)
        inputs (vec (for [_ (range num-inputs)]
                      (parse-tx-in stream)))
        num-outputs (read-varint stream)
        outputs (vec (for [_ (range num-outputs)]
                       (parse-tx-out stream)))
        inputs (vec (for [tx-in inputs
                          :let [num-items (read-varint stream),
                                items (vec (for [_ (range num-items)
                                                 :let [item-len (read-varint stream)]]
                                             (if (= 0 item-len) 0
                                                 (read-bytes stream item-len))))]]
                      (assoc tx-in :witness items)))
        locktime (le-bytes->num (read-bytes stream 4))]
  (->Tx "tx" version inputs outputs locktime testnet? true))

(defnc parse-tx [^InputStream stream testnet?]
  :do (.mark stream 10)
  :let [_ (read-bytes stream 4),
        segwit-marker (.read stream),
        parse-method (if (= segwit-marker 0) parse-tx-segwit parse-tx-legacy)]
  :do (.reset stream)
  (parse-method stream testnet?))

(defn serialize-tx-legacy ^bytes [{:keys [version tx-ins tx-outs locktime]}]
  (byte-array
   (concat (le-num->bytes 4 version)
           (encode-varint (count tx-ins))
           (apply concat (for [tx-in tx-ins] (serialize-tx-in tx-in)))
           (encode-varint (count tx-outs))
           (apply concat (for [tx-out tx-outs] (serialize-tx-out tx-out)))
           (le-num->bytes 4 locktime))))

(defn serialize-tx-segwit ^bytes [{:keys [version tx-ins tx-outs locktime]}]
  (byte-array
   (concat (le-num->bytes 4 version)
           [0 1]
           (encode-varint (count tx-ins))
           (apply concat (for [tx-in tx-ins] (serialize-tx-in tx-in)))
           (encode-varint (count tx-outs))
           (apply concat (for [tx-out tx-outs] (serialize-tx-out tx-out)))
           (apply concat
                  (for [{:keys [witness] :as tx-in} tx-ins]
                    (concat (le-num->bytes 1 (count witness))
                            (apply concat
                                   (for [item witness]
                                     (if (integer? item)
                                       (le-num->bytes 1 item)
                                       (concat (encode-varint (count item)) item)))))))
           (le-num->bytes 4 locktime))))

(defnc serialize-tx [tx]
  (:segwit? tx) (serialize-tx-segwit tx) (serialize-tx-legacy tx))

(defn hash-tx [tx]
  (byte-array (reverse (hash256 (serialize-tx-legacy tx)))))

(defn id [tx]
  (bytes->hex (hash-tx tx)))

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

(defnc hash-prevouts [{:keys [tx-ins]}]
  :let [all-prevouts (byte-array
                      (apply concat (for [{:keys [prev-tx prev-index]} tx-ins]
                                      (concat (reverse prev-tx)
                                              (le-num->bytes 4 prev-index)))))]
  (hash256 all-prevouts))
(def hash-prevouts (memoize/fifo hash-prevouts))

(defnc hash-sequence [{:keys [tx-ins]}]
  :let [all-sequence (byte-array
                      (apply concat (for [{:keys [sequence]} tx-ins]
                                      (le-num->bytes 4 sequence))))]
  (hash256 all-sequence))
(def hash-sequence (memoize/fifo hash-sequence))

(defnc hash-outputs [{:keys [tx-outs]}]
  :let [all-outputs (byte-array
                     (apply concat (for [tx-out tx-outs]
                                     (serialize-tx-out tx-out))))]
  (hash256 all-outputs))
(def hash-outputs (memoize/fifo hash-outputs))

(defnc sig-hash-bip143 [{:keys [tx-ins version locktime testnet?] :as tx}
                        input-index redeem-script witness-script]
  :let [{:keys [prev-tx prev-index sequence] :as tx-in} (nth tx-ins input-index),
        bytes
        (byte-array
         (concat (le-num->bytes 4 version)
                 (hash-prevouts tx) (hash-sequence tx)
                 (reverse prev-tx) (le-num->bytes 4 prev-index)
                 (cond
                   witness-script (script/serialize-script witness-script)
                   redeem-script (script/serialize-script
                                  (script/p2pkh-script (nth redeem-script 1)))
                   :else (script/serialize-script
                          (script/p2pkh-script
                           (nth (script-pubkey-tx-in tx-in testnet?) 1))))
                 (le-num->bytes 8 (amount-tx-in tx-in testnet?))
                 (le-num->bytes 4 sequence)
                 (hash-outputs tx)
                 (le-num->bytes 4 locktime)
                 (le-num->bytes 4 SIGHASH_ALL)))]
  (bytes->num (hash256 bytes)))


(defnc verify-tx-in [{:keys [tx-ins testnet?] :as tx} input-index]
  :let [{:keys [script-sig] :as tx-in} (nth tx-ins input-index),
        script-pubkey (script-pubkey-tx-in tx-in testnet?)
        [z witness]
        (cond
          (script/p2sh-script? script-pubkey)
          (cond
            :let [cmd (last script-sig),
                  raw-redeem (bytes/concat (encode-varint (count cmd))
                                           cmd)
                  redeem-script (script/parse-script (io/input-stream raw-redeem))]
            (script/p2wpkh-script? redeem-script)
            [(sig-hash-bip143 tx input-index redeem-script nil) (:witness tx-in)]
            (script/p2wsh-script? redeem-script)
            (let [cmd (last (:witness tx-in)),
                  raw-witness (bytes/concat (encode-varint (count cmd)) cmd),
                  witness-script (script/parse-script (io/input-stream raw-witness))]
              [(sig-hash-bip143 tx input-index nil witness-script) (:witness tx-in)])
            :else
            [(sig-hash tx input-index redeem-script) nil])
          (script/p2wpkh-script? script-pubkey)
          [(sig-hash-bip143 tx input-index nil nil) (:witness tx-in)]
          (script/p2wsh-script? script-pubkey)
          (let [cmd (last (:witness tx-in)),
                raw-witness (bytes/concat (encode-varint (count cmd)) cmd),
                witness-script (script/parse-script (io/input-stream raw-witness))]
            [(sig-hash-bip143 tx input-index nil witness-script) (:witness tx-in)])
          :else [(sig-hash tx input-index) nil]),
        script (concat script-sig script-pubkey)]
  (script/evaluate-script script z witness))

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

(defnc coinbase-tx? [{[{:keys [prev-tx prev-index]} :as tx-ins] :tx-ins :as tx}]
  (and (= (count tx-ins) 1)
       (bytes/equals? prev-tx (byte-array (repeat 32 (byte 0))))
       (= prev-index 0xffffffff)))

(defnc coinbase-height [{[{:keys [script-sig]}] :tx-ins :as coinbase-tx}]
  :when (coinbase-tx? coinbase-tx)
  (le-bytes->num (nth script-sig 0)))

