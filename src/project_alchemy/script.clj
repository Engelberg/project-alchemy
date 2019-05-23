(ns project-alchemy.script
  (:refer-clojure :exclude [cond])
  (:require [better-cond.core :refer [cond defnc defnc-]]  
            [project-alchemy.helper :refer [read-bytes read-varint encode-varint le-bytes->num le-num->bytes hash256 unsigned-byte]]
            [buddy.core.bytes :as bytes]
            [buddy.core.codecs :refer :all]
            [buddy.core.hash :as h]
            [project-alchemy.op :as op :refer [op-code-functions op-code-names]]
            [clojure.tools.logging :as log]
            [clojure.java.io :as io]
            [project-alchemy.ecc :as ecc]
            [project-alchemy.helper :as helper]
            [project-alchemy.script :as script])
  (:import java.io.InputStream java.util.Stack))

(defnc parse-script [^InputStream stream]
  :let [length (read-varint stream)
        [cmds ctr]
        (loop [cmds [] ctr 0]
          (cond
            (>= ctr length) [cmds ctr],
            :let [current (read-bytes stream 1), ctr (inc ctr),
                  current-byte (unsigned-byte (nth current 0))]
            (and (>= current-byte 1) (<= current-byte 75))
            (recur (conj cmds (read-bytes stream current-byte))
                   (+ ctr current-byte)),
            (= current-byte 76)
            (let [data-length (le-bytes->num (read-bytes stream 1))]
              (recur (conj cmds (read-bytes stream data-length))
                     (+ ctr data-length 1)))
            (= current-byte 77)
            (let [data-length (le-bytes->num (read-bytes stream 2))]
              (recur (conj cmds (read-bytes stream data-length))
                     (+ ctr data-length 2)))
            :else (recur (conj cmds current-byte) ctr)))]
  (not= ctr length) (throw (ex-info "Parsing script failed"
                                    {:cmds cmds, :ctr ctr, :length length}))
  cmds)

(defn raw-serialize-script ^bytes [script]
  (loop [result [] script (seq script)]    
    (cond
      (nil? script) (byte-array result)
      :let [cmd (first script), script (next script)]
      (number? cmd) (recur (into result (le-num->bytes 1 cmd)) script)
      :let [len (count cmd)]
      (< len 75) (recur (into (into result (le-num->bytes 1 len)) cmd) script)
      (and (> len 75) (< len 0x100)) (recur (-> (into result (le-num->bytes 1 76))
                                                (into (le-num->bytes 1 len))
                                                (into cmd))
                                            script)
      (and (>= len 0x100) (<= len 520)) (recur (-> result
                                                   (into (le-num->bytes 1 77))
                                                   (into (le-num->bytes 2 len))
                                                   (into cmd))
                                               script)
      :else (throw (ex-info "Too long cmd" {:cmd cmd, :length len})))))

(defn serialize-script ^bytes [script]
  (let [raw (raw-serialize-script script),
        length (count raw)]
    (bytes/concat (encode-varint length) raw)))

;; Book notes that the following evaluation method is not totally safe because
;; it fails to implement proper isolation between sig and pubkey

(defnc p2sh-rule [[cmd0 cmd1 cmd2 :as script] ^Stack stack cmd]
  (and (= (count script) 3)
       (= cmd0 0xa9)
       (bytes? cmd1)
       (= (count cmd1) 20)
       (= cmd2 0x87))
  (cond
    (not (op/op-hash160 stack)) false
    :do (.push stack cmd1)
    (not (op/op-equal stack)) false
    (not (op/op-verify stack))  (do (log/info "bad p2sh h160") false)
    :let [redeem-script (bytes/concat (encode-varint (count cmd))
                                      cmd)]
    (parse-script (io/input-stream redeem-script)))
  script)

(declare p2pkh-script)
(defnc p2wpkh-rule [script ^Stack stack witness]
  :let [vstack (vec stack)]
  (and (= (count stack) 2) (bytes/equals? (nth vstack 0) (byte-array []))
       (= (count (nth vstack 1)) 20))
  (let [h160 (.pop stack),
        _ (.pop stack)]
    (concat script witness (p2pkh-script h160)))
  script)

(defnc p2wsh-rule [script ^Stack stack witness]
  :let [vstack (vec stack)]
  (and (= (count stack) 2) (bytes/equals? (nth vstack 0) (byte-array []))
       (= (count (nth vstack 1)) 32))
  (cond
    :let [s256 (.pop stack),
          _ (.pop stack)
          script (concat script (drop-last 1 witness))
          witness-script (last witness)]
    (not (bytes/equals? s256 (h/sha256 witness-script)))
    (do (log/info "bad sha256" (bytes->hex s256)
                  (bytes->hex (h/sha256 witness-script)))
        false)
    (concat script (script/parse-script (io/input-stream
                                         (bytes/concat
                                          (encode-varint (count witness-script))
                                          witness-script)))))
  script)

(defnc evaluate-script [script z witness]
  :let [stack (Stack.) altstack (Stack.),
        result (loop [script (seq script)]
                 (cond
                   (nil? script) true
                   :let [cmd (first script) script (next script)]
                   (not (number? cmd))
                   (cond
                     :do (.push stack cmd)
                     :let [script (p2sh-rule script stack cmd),
                           script (p2wpkh-rule script stack witness),
                           script (p2wsh-rule script stack witness)]
                     (recur script))
                   :let [op (op-code-functions cmd)]
                   (#{99 100} cmd) (let [a-items (atom script)]
                                     (if-not (op stack a-items)
                                       (do (log/info "bad op" (op-code-names cmd))
                                           false)
                                       (recur @a-items)))
                   (#{107 108} cmd) (if-not (op stack altstack)
                                      (do (log/info "bad op" (op-code-names cmd))
                                          false)
                                      (recur script))
                   (#{172 173 174 175} cmd) (if-not (op stack z)
                                              (do (log/info "bad op" (op-code-names cmd))
                                                  false)
                                              (recur script))
                   :else (if-not (op stack)
                           (do (log/info "bad op" (op-code-names cmd)) false)
                           (recur script))))]
  (not result) false
  (= (count stack) 0) false
  (= (count (.pop stack)) 0) false
  true)

(defn p2pkh-script [h160]
  [0x76 0xa9 h160 0x88 0xac])

(defn p2pkh-script? [[cmd0 cmd1 cmd2 cmd3 cmd4 :as cmds]]
  (and (= (count cmds) 5)
       (= cmd0 0x76) (= cmd1 0xa9)
       (bytes? cmd2) (= (count cmd2) 20)
       (= cmd3 0x88) (= cmd4 0xac)))

(defn p2sh-script [h160]
  [0xa9 h160 0x87])

(defn p2sh-script? [[cmd0 cmd1 cmd2 :as cmds]]
  (and (= (count cmds) 3)
       (= cmd0 0xa9) (bytes? cmd1) (= (count cmd1) 20) (= cmd2 0x87)))

(defn p2wpkh-script [h160]
  [0x00 h160])

(defn p2wpkh-script? [[cmd0 cmd1 :as cmds]]
  (and (= (count cmds) 2)
       (= cmd0 0x00) (bytes? cmd1) (= (count cmd1) 20)))

(defn p2wsh-script [h256]
  [0x00 h256])

(defn p2wsh-script? [[cmd0 cmd1 :as cmds]]
  (and (= (count cmds) 2)
       (= cmd0 0x00) (bytes? cmd1) (= (count cmd1) 32)))

(defnc address [script testnet?]
  (p2pkh-script? script) (ecc/h160->p2pkh-address (nth script 2) testnet?)
  (p2sh-script? script) (ecc/h160->p2sh-address (nth script 1) testnet?))

