(ns project-alchemy.helper
  (:refer-clojure :exclude [cond])
  (:require [better-cond.core :refer [cond defnc defnc-]]
            [buddy.core.hash :as h])
  (:import java.io.InputStream))

(defn read-bytes ^bytes [^InputStream stream length]
  (let [buffer (byte-array length)]
    (.read stream buffer)
    buffer))

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
      (byte-array (drop (- l length) (seq a)))
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

