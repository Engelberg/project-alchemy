(ns project-alchemy.helper
  (:refer-clojure :exclude [cond])
  (:require [better-cond.core :refer [cond defnc defnc-]]
            [buddy.core.codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [buddy.core.hash :as h]
            [clojure.math.numeric-tower :as m])
  (:import java.io.InputStream))

(def TWO_WEEKS (* 60 60 24 14))
(def MAX_TARGET 0x00000000FFFF0000000000000000000000000000000000000000000000000000)

(defn read-bytes ^bytes [^InputStream stream length]
  (let [buffer (byte-array length)]
    (.read stream buffer)
    buffer))

(defn unsigned-byte [b]
  (if (neg? b) (+ 256 b) b))

;; big endian encoding and decoding

(defn num->bytes "Big endian encoding"
  ^bytes [length n]
  (let [a (.toByteArray (biginteger n)),
        l (count a),
        zeros (repeat (- length l) (byte 0))]
    ;; unsigned 32-byte num produces 33 bytes with leading 0,
    ;; which needs to be dropped
    (if (> l length) 
      (byte-array (drop (- l length) (seq a)))
      (byte-array (concat zeros a)))))

(defn bytes->num "Interprets as unsigned 256-bit number" [bs]
  (BigInteger. (byte-array (into [0] bs))))

;; little endian encoding and decoding

(defn le-bytes->num "little endian decoding" [bs]
  (bytes->num (reverse bs)))

(defn le-num->bytes "little endian encoding"
  ^bytes [length n]
  (let [a (.toByteArray (biginteger n)),
        l (count a),
        zeros (repeat (- length l) (byte 0))]
    (if (> l length) 
      (byte-array (reverse (drop (- l length) (seq a))))
      (byte-array (reverse (concat zeros a))))))

;; hashing

(defn hash160 [bs]
  (h/ripemd160 (h/sha256 bs)))

(defn hash256 [bs]
  (h/sha256 (h/sha256 bs)))

;; varints

(defnc read-varint [^InputStream stream]
  :let [i (.read stream)]
  (case i
    0xfd (le-bytes->num (read-bytes stream 2))
    0xfe (le-bytes->num (read-bytes stream 4))
    0xff (le-bytes->num (read-bytes stream 8))
    i))

(defn ^bytes encode-varint [i]
  (cond
    (< i 0xfd) (byte-array [(unchecked-byte i)])
    (< i 0x10000) (byte-array (cons (unchecked-byte 0xfd) (le-num->bytes 2 i)))
    (< i 0x100000000) (byte-array (cons (unchecked-byte 0xfe) (le-num->bytes 4 i)))
    (< i 0x10000000000000000) (byte-array (cons (unchecked-byte 0xff) (le-num->bytes 8 i)))
    :else (throw (ex-info "Integer too large" {:integer i}))))

(defnc bits->target [^bytes bits]
  :let [exponent (nth bits 3),
        coefficient (le-bytes->num (bytes/slice bits 0 3))]
  (*' coefficient (m/expt 256 (- exponent 3))))

(defn target->bits ^bytes [target]
  (cond
    :let [bytes (into [] (drop-while #{0}) (seq (num->bytes 32 target)))
          [exponent coefficient] (if (> (nth bytes 0) 0x7f)
                                   [(inc (count bytes)) (cons [0] (subvec bytes 0 2))]
                                   [(count bytes) (subvec bytes 0 3)])]
    (byte-array (concat (reverse coefficient) [(unchecked-byte exponent)]))))

(defnc calculate-new-bits [prev-bits time-differential]
  :let [time-differential (cond (> time-differential (* 4 TWO_WEEKS)) (* 4 TWO_WEEKS)
                                (< time-differential (/ TWO_WEEKS 4)) (/ TWO_WEEKS 4)
                                :else time-differential),
        prev-target (bits->target prev-bits)
        new-target (min MAX_TARGET (/ (* prev-target time-differential) TWO_WEEKS))]
  (target->bits new-target))

