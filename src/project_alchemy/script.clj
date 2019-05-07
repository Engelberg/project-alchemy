(ns project-alchemy.script
  (:refer-clojure :exclude [cond])
  (:require [better-cond.core :refer [cond defnc defnc-]]  
            [project-alchemy.helper :refer [read-bytes read-varint encode-varint le-bytes->num le-num->bytes hash256 unsigned-byte]]
            [buddy.core.bytes :as bytes]
            [buddy.core.codecs :refer :all]
            [project-alchemy.op :as op :refer [op-code-functions op-code-names]]
            [clojure.tools.logging :as log])
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

(defnc evaluate-script [script z]
  :let [stack (Stack.) altstack (Stack.),
        result (loop [script (seq script)]
                 (cond
                   (nil? script) true
                   :let [cmd (first script) script (next script)]
                   (not (number? cmd)) (do (.push stack cmd) (recur script))
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
                   
      
