(ns ^{:author "Mark Engelberg",
      :doc "A Clojure port of chapter 9 of Programming Bitcoin"}
    project-alchemy.network
  (:refer-clojure :exclude [cond])
  (:require [better-cond.core :refer [cond defnc defnc-]]
            [project-alchemy.helper :refer [read-bytes read-varint encode-varint
                                            le-bytes->num le-num->bytes hash256]
             :as helper]
            [project-alchemy.block :as block]
            [project-alchemy.merkle-block :as merkle]
            [project-alchemy.tx :as tx]
            [project-alchemy.bloomfilter :as bloom]
            [buddy.core.codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [clojure.java.io :as io]
            [medley.core :as medley]
            [aleph.tcp :as tcp]
            [project-alchemy.ecc :as ecc]
            [buddy.core.nonce :as nonce]
            [manifold.deferred :as d]
            [manifold.stream :as s]
            [aleph.tcp :as tcp]
            [byte-streams]
            [clojure.pprint :refer [pprint]]
            [clojure.tools.logging :as log]
            [project-alchemy.script :as script])            
  (:import java.io.InputStream))

(def TX_DATA_TYPE 1)
(def BLOCK_DATA_TYPE 2)
(def FILTERED_BLOCK_DATA_TYPE 3)
(def COMPACT_BLOCK_DATA_TYPE 4)

(def NETWORK_MAGIC (byte-array (map unchecked-byte [0xf9 0xbe 0xb4 0xd9])))
(def TESTNET_NETWORK_MAGIC (byte-array (map unchecked-byte [0x0b 0x11 0x09 0x07])))

(defnc magic [{:keys [testnet?]}]
  testnet? TESTNET_NETWORK_MAGIC NETWORK_MAGIC)

(defrecord NetworkEnvelope [command payload testnet?])

(defnc pprint-NetworkEnvelope [{:keys [magic command payload testnet?]}]
  (print (->NetworkEnvelope (String. command) (bytes->hex (bytes/slice payload 0 40)) testnet?)))
(. clojure.pprint/simple-dispatch addMethod NetworkEnvelope pprint-NetworkEnvelope)

(defn parse-network-envelope ^bytes [^InputStream stream]
  (cond
    :let [magic (read-bytes stream 4)
          command (byte-array (remove #{0} (read-bytes stream 12)))
          payload-length (le-bytes->num (read-bytes stream 4))
          payload-checksum (read-bytes stream 4)
          payload (read-bytes stream payload-length)
          payload-hash (hash256 payload)
          payload-computed-checksum (bytes/slice payload-hash 0 4)]
    (not (bytes/equals? payload-checksum payload-computed-checksum))
    (throw (ex-info "Invalid payload" {:command (String. command),
                                       :payload-length payload-length,
                                       :actual-payload-length (count payload)
                                       :payload payload,
                                       :payload-checksum payload-checksum,
                                       :payload-hash payload-hash
                                       :payload-computed-checksum payload-computed-checksum}))
    (bytes/equals? magic NETWORK_MAGIC) (NetworkEnvelope. command payload false)
    (bytes/equals? magic TESTNET_NETWORK_MAGIC) (NetworkEnvelope. command payload true)
    :else (throw (ex-info "Invalid network magic" {:magic magic}))))

(defnc serialize-network-envelope [{:keys [command payload] :as ne}]
  (byte-array (concat (magic ne) command (repeat (- 12 (count command)) 0)
                      (le-num->bytes 4 (count payload))
                      (bytes/slice (hash256 payload) 0 4)
                      payload)))

(defrecord VersionMessage [command-name version services timestamp receiver-services
                           receiver-ip receiver-port sender-services
                           sender-ip sender-port nonce user-agent
                           latest-block relay?])
(defnc map->VersionMessage [m]
  :let [{:keys [version services timestamp receiver-services
                receiver-ip receiver-port sender-services sender-ip
                sender-port nonce user-agent latest-block relay?]}
        (merge {:version 70015, :services 0, :receiver-services 0
                :receiver-ip (byte-array (repeat 4 0)) :receiver-port 8333
                :sender-services 0, :sender-ip (byte-array (repeat 4 0)),
                :sender-port 8333 :user-agent "project-alechemy",
                :latest-block 0, :relay? false,
                :timestamp (quot (System/currentTimeMillis) 1000)
                :nonce (nonce/random-bytes 8)}
               m)]
  (->VersionMessage "version" version services timestamp receiver-services
                    receiver-ip receiver-port sender-services sender-ip
                    sender-port nonce user-agent latest-block relay?))

(defmulti serialize-message :command-name)
(defmulti parse-message (fn [{:keys [command-name]} payload] command-name))

(defmethod serialize-message "version"
  [{:keys [version services timestamp receiver-services
           receiver-ip receiver-port sender-services sender-ip
           sender-port nonce user-agent latest-block relay?]}]
  (byte-array
   (concat (le-num->bytes 4 version) (le-num->bytes 8 services)
           (le-num->bytes 8 timestamp) (le-num->bytes 8 receiver-services)
           (hex->bytes "00000000000000000000ffff") receiver-ip
           (le-num->bytes 2 receiver-port) (le-num->bytes 8 sender-services)
           (hex->bytes "00000000000000000000ffff") sender-ip
           (le-num->bytes 2 sender-port) nonce
           (encode-varint (count user-agent)) (.getBytes ^String user-agent)
           (le-num->bytes 4 latest-block)
           (if relay? [1] [0]))))

(defmethod parse-message "version" [_ payload]
  {:command-name "version" :payload payload})

(defmethod serialize-message "verack" [_] (byte-array []))
(defmethod parse-message "verack" [_ _] {:command-name "verack"})

(defmethod serialize-message "ping" [{nonce :nonce}] nonce)
(defmethod parse-message "ping" [_ ^InputStream payload]
  {:command-name "ping", :nonce (read-bytes payload 8)})

(defmethod serialize-message "pong" [{nonce :nonce}] nonce)
(defmethod parse-message "pong" [_ ^InputStream payload]
  {:command-name "pong", :nonce (read-bytes payload 8)})

(defrecord GetHeadersMessage [command-name version num-hashes start-block end-block])
(defnc map->GetHeadersMessage [m]
  :let [{:keys [version num-hashes start-block end-block]}
        (merge {:version 70015, :num-hashes 1, :end-block (byte-array (repeat 32 0))}
               m)]
  :do (assert start-block "a start block is required")
  (GetHeadersMessage. "getheaders" version num-hashes start-block end-block))

(defmethod serialize-message "getheaders"
  [{:keys [version num-hashes start-block end-block]}]
  (byte-array (concat (le-num->bytes 4 version) (encode-varint num-hashes)
                      (reverse start-block) (reverse end-block))))

(defmethod parse-message "headers" [_ ^InputStream payload]
  (cond
    :let [num-headers (read-varint payload),
          blocks (for [_ (range num-headers)
                       :let [block (block/parse-block payload),
                             num-txs (read-varint payload)]]
                   (if (not= num-txs 0)
                     (throw (ex-info "Number of txs not 0" {:num-txs num-txs}))
                     block))]
    {:command-name "headers", :blocks (vec blocks)}))

(defmethod serialize-message "getdata" [{:keys [data]}]
  (byte-array (concat (encode-varint (count data))
                      (mapcat (fn [[data-type identifier]]
                                (concat (le-num->bytes 4 data-type)
                                        (reverse identifier)))
                              data))))

(defmethod parse-message "merkleblock" [_ ^InputStream payload]
  (merkle/parse-merkle-block payload))

(defmethod parse-message "tx" [{:keys [testnet?]} ^InputStream payload]
  (tx/parse-tx payload testnet?))
(defmethod serialize-message "tx" [tx]
  (tx/serialize-tx tx))

(defmethod parse-message :default [_ _] nil)
(defmethod serialize-message :default [{:keys [payload]}] payload)

(defnc encode-message
  "Wraps message in network envelope"
  [{:keys [testnet? logging?]} {:keys [command-name] :as msg}]
  :let [envelope (->NetworkEnvelope (.getBytes ^String command-name) (serialize-message msg)
                                    testnet?)]
  :do (when logging? (log/info "Sending" (with-out-str (pprint envelope))))
  (serialize-network-envelope envelope))

(defnc decode-message [{:keys [logging? testnet?]} ^InputStream stream]
  :let [{:keys [command payload] :as envelope}
        (parse-network-envelope stream),
        command-name (String. command)]
  :do (def envelope envelope)
  :do (when logging? (log/info "Receiving" (with-out-str (pprint envelope))))
  (parse-message {:command-name command-name, :testnet? testnet?}
                 (io/input-stream payload)))

(defnc simple-node [options]
  :let [node (merge {:host "testnet.programmingbitcoin.com", :testnet? true,
                     :port (if (false? (:testnet? options)) 8333 18333)} options),
        client (tcp/client node)
        s @client]
  (assoc node :duplex-stream s :input-stream (byte-streams/to-input-stream s)))

(defnc send-message [node message]
  @(s/put! (:duplex-stream node) (encode-message node message)))

(defnc receive-message [node]
  (decode-message node (:input-stream node)))

(defn wait-for [node command-names]
  (loop []
    (cond
      :let [{:keys [:command-name] :as msg} (receive-message node)]
      :do (when (= command-name "version")
            (send-message node {:command-name "verack"}))
      :do (when (= command-name "ping")
            (send-message node (assoc msg :command-name "pong")))
      (contains? command-names command-name) msg
      (recur))))

(defn handshake [node]
  (send-message node (map->VersionMessage {}))
  (loop [verack-received? false version-received? false]
    (cond
      (and verack-received? version-received?) true
      :let [msg (wait-for node #{"version" "verack"})
            cn (:command-name msg)]
      (= cn "version") (recur verack-received? true)
      (= cn "verack") (recur true version-received?))))

(defn check-blocks []
  (let [previous (atom (block/parse-block (io/input-stream block/GENESIS_BLOCK))),
        hash-previous #(block/hash-block @previous)
        first-epoch-timestamp (atom (:timestamp @previous)),
        expected-bits (atom block/LOWEST_BITS),
        node (simple-node {:host "mainnet.programmingbitcoin.com" :testnet? false
                           :logging? true})
        count (atom 1)]
    ;; (add-watch previous :watcher
    ;;            (fn [key atom old-state new-state]
    ;;              (println "New timestamp:" (:timestamp new-state))))
    (handshake node)
    (dotimes [i 19]      
      (let [getheaders (map->GetHeadersMessage {:start-block (hash-previous)})
            _ (send-message node getheaders)
            headers (wait-for node #{"headers"})]
        (doseq [header (:blocks headers)]
          (cond
            (not (block/valid-pow? header))
            (throw (ex-info "Bad PoW at block" {:count @count})),
            (not (bytes/equals? (:prev-block header) (hash-previous)))
            (throw (ex-info "Discontinuous block" {:count @count,
                                                   :prev-block-header
                                                   (bytes->hex (:prev-block header)),
                                                   :hash-previous
                                                   (bytes->hex (hash-previous))})),
            :do (when (and (not= 0 @count) (= 0 (mod @count 2016)))
                  (let [time-diff (- (:timestamp @previous)
                                     @first-epoch-timestamp)]
                    (reset! expected-bits (helper/calculate-new-bits
                                           (:bits @previous) time-diff))
                    (println (bytes->hex @expected-bits))
                    (reset! first-epoch-timestamp (:timestamp header))))
            (not (bytes/equals? (:bits header) @expected-bits))
            (throw (ex-info "bad bits at block"
                            {:count @count
                             :bits-header (bytes->hex (:bits header))
                             :expected-bits (bytes->hex @expected-bits)}))
            (do (swap! count inc) (reset! previous header))))))))

;; The following code is based on sample from the book, but the book code
;; is deficient in several ways. It assumes merkle proof comes before tx,
;; and it doesn't ensure the proof is for the tx in question.

(defnc get-transaction-of-interest [last-block-hex address testnet?]
  :let [h160 (ecc/decode-base58 address),
        node (simple-node {:testnet? true, :logging? false}),
        bf (bloom/add-to-filter (bloom/->BloomFilter 30 5 90210) h160)
        start-block (hex->bytes last-block-hex)]
  :do (handshake node)
  :do (send-message node (bloom/filterload bf))
  :do (send-message node (map->GetHeadersMessage {:start-block start-block}))
  :let [headers (wait-for node #{"headers"})
        data (for [b (:blocks headers)]
               (if (not (block/valid-pow? b))
                 (throw (ex-info "Proof of work invalid" b))
                 [FILTERED_BLOCK_DATA_TYPE (block/hash-block b)]))]
  :do (send-message node {:command-name "getdata", :data data})
  (loop []
    (cond
      :let [message (wait-for node #{"merkleblock" "tx"})]
      (= (:command-name message) "merkleblock")
      (do (println "Checking merkle proof")
          (assert (merkle/valid-merkle-block? message) "Invalid merkle proof")
          (recur)),
      :let [matching-txs (for [[i tx-out] (medley/indexed (:tx-outs message))
                               :when (= address (script/address
                                                 (:script-pubkey tx-out)
                                                 testnet?))]
                           [(tx/id message) i])]
      (seq matching-txs) matching-txs
      :else (recur))))
                           
