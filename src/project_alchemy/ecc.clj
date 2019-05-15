(ns ^{:author "Mark Engelberg",
      :doc "A Clojure port of chapters 1-4 of Programming Bitcoin"}
    project-alchemy.ecc
  (:refer-clojure :exclude [+ - * / cond])
  (:require [clojure.math.numeric-tower :as nt]
            [better-cond.core :refer [cond defnc defnc-]]
            [project-alchemy.helper :refer [hash160 hash256 read-bytes
                                            bytes->num num->bytes]]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :refer :all]
            [buddy.core.bytes :as bytes])
  (:import java.util.Arrays
           java.security.SecureRandom
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

(declare S256Point?)
(def P (clojure.core/- (nt/expt 2 256) (nt/expt 2 32) 977))
(def N 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141)

(defn mod-pow [number power modulus]
  (.modPow (biginteger number) (biginteger power) (biginteger modulus)))

(defn mod-inverse [number modulus]
  (.modInverse (biginteger number) (biginteger modulus)))

(defprotocol FieldOps
  (+ [x y])
  (- [x y])
  (* [x y])
  (/ [x y])
  (expt [x exponent])
  (zero [x]))

(defn scalar-multiply [n z]
  (if (zero? n) (zero z)
      (loop [n n, y (zero z), z z]
        (let [t (even? n), n (quot n 2)]
          (cond
            t (recur n y (+ z z))
            (zero? n) (+ z y)
            :else (recur n (+ z y) (+ z z)))))))

(extend-type Number
  FieldOps
  (+ [x y] (+' x y))
  (- [x y] (-' x y))
  (* [x y] (cond
             (number? y) (*' x y)
             (S256Point? y) (scalar-multiply (mod x N) y)
             :else (scalar-multiply x y)))
  (/ [x y] (clojure.core// x y))
  (zero [x] 0)
  (expt [x exponent] (nt/expt x exponent)))

(defrecord FieldElement [num prime]
  FieldOps
  (+ [x {num2 :num, prime2 :prime}]
    (assert (= prime prime2) "Cannot add number from two different fields")
    (FieldElement. (mod (+' num num2) prime) prime))
  (- [x {num2 :num, prime2 :prime}]
    (assert (= prime prime2) "Cannot subtract number from two different fields")
    (FieldElement. (mod (-' num num2) prime) prime))
  (* [x {num2 :num, prime2 :prime}]
    (assert (= prime prime2) "Cannot multiply number from two different fields")
    (FieldElement. (mod (*' num num2) prime) prime))
  (/ [x {num2 :num, prime2 :prime}]
    (assert (= prime prime2) "Cannot divide number from two different fields")
    (FieldElement. (mod (*' num (mod-inverse num2 prime)) prime) prime))
  (zero [x] (FieldElement. 0 prime))
  (expt [x exponent]
    (let [exponent (mod exponent (dec prime))]
      (FieldElement. (mod-pow num exponent prime) prime))))

(defn ->FieldElement [num prime]
  (assert (and (<= 0 num) (< num prime)))
  (FieldElement. num prime))

(defrecord Point [x y a b]
  FieldOps
  (zero [p] (Point. nil nil a b))
  (+ [p1 {x2 :x y2 :y a2 :a b2 :b :as p2}]
    (assert (and (= a a2) (= b b2)) "Points must be on the same curve")
    (cond
      (nil? x) p2
      (nil? x2) p1
      (and (= x x2) (not= y y2)) (Point. nil nil a b)
      (= p1 p2) (if (= y (zero x)) (Point. nil nil a b)
                    (let [s (/ (+ (* 3 (expt x 2)) a) (* 2 y)),
                          x3 (- (expt s 2) (* 2 x))
                          y3 (- (* s (- x x3)) y)]
                      (Point. x3 y3 a b)))
      :else (let [s (/ (- y2 y) (- x2 x)),
                  x3 (- (- (expt s 2) x) x2),
                  y3 (- (* s (- x x3)) y)]
              (Point. x3 y3 a b)))))

(defn valid-point? [x y a b]
  (or (= x y nil)
      (= (expt y 2) (+ (+ (expt x 3) (* a x)) b))))

(defn ->Point [x y a b]
  (assert (valid-point? x y a b) "Point not on curve")
  (Point. x y a b))

(def A (->FieldElement 0 P))
(def B (->FieldElement 7 P))

(defn ->S256Point
  "Takes two numbers from 0 to P-1, passes through nil or FieldElements"
  [x y]
  (let [x (if (number? x) (->FieldElement x P) x),
        y (if (number? y) (->FieldElement y P) y)]
    (->Point x y A B)))

(defn S256Point? [{:keys [a b]}] (and (= a A) (= b B)))

(def G (->S256Point
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8))

(defrecord Signature [r s])

(defnc verify-signature
  "Takes a public-key (point on secp256k1 curve), z (256-bit hash of some data), and a signature (comprised of r and s)"
  [public-key z {:keys [r s]}]
  :let [s-inv (mod-inverse s N),
        u (mod (* z s-inv) N),
        v (mod (* r s-inv) N),
        total (+ (* u G) (* v public-key))]
  (= (-> total :x :num) r))

;; PrivateKey tracks a secret 256-bit number and the corresponding public-key,
;; which is a point on the secp256k1 curve
(defrecord PrivateKey [secret point])

(defn ->PrivateKey [secret]
  (PrivateKey. secret (* secret G)))

;; First version of signing algo uses random number for nonce
(defn rand-256 "Generates a random 256 bit number" []
  (bytes->num (nonce/random-bytes 32)))
(defnc rand-N "Generates a random number in Z_N" []
  :let [i (rand-256)]
  (< i N) i
  (recur))

;; Second version of signing algo uses deterministic nonce
(defn hmac ^bytes [^bytes key ^bytes message]
  (let [hasher (Mac/getInstance "HmacSHA256"),
        _ (.init hasher (SecretKeySpec. key "HmacSHA256"))]
    (.doFinal hasher message)))

(defn deterministic-k "Generates a k from secret and z"
  [secret z]
  (let [k (byte-array 32 (byte 0))
        v (byte-array 32 (byte 1))
        z (if (> z N) (- z N) z)
        z-bytes (num->bytes 32 z)
        secret-bytes (num->bytes 32 secret)
        k (hmac k (byte-array (concat v [0] secret-bytes z-bytes)))
        v (hmac k v)
        k (hmac k (byte-array (concat v [1] secret-bytes z-bytes)))
        v (hmac k v)]
    (loop [k k v v]
      (cond
        :let [v (hmac k v)
              candidate (bytes->num v)]
        (and (<= 1 candidate) (< candidate N)) candidate
        :let [k (hmac k (byte-array (concat v [0]))),
              v (hmac k v)]
        (recur k v)))))

(defnc sign "Takes a PrivateKey and a 256-bit hash, produces Signature"
  [{:keys [secret point]} z]
  :let [k (deterministic-k secret z) ;; (rand-N),
        r (-> (* k G) :x :num),
        k-inv (mod-inverse k N),
        s (mod (* (+ z (* r secret)) k-inv) N)]
  (> s (quot N 2)) (->Signature r (- N s))
  :else (->Signature r s))

;; Serialization

(defn sec "Uncompressed SEC format of ECDSA public key"
  (^bytes [point] (sec point true))
  (^bytes [{:keys [x y]} compressed?]
   (cond
     (not compressed?)
     (byte-array
      (concat [4] (num->bytes 32 (:num x)) (num->bytes 32 (:num y))))
     (byte-array
      (concat (if (even? (:num y)) [2] [3]) (num->bytes 32 (:num x)))))))

;; Currently doesn't give meaningful errors if bytes are wrong length
(defnc parse-sec "Parses SEC bytes" [^bytes sec-bytes]
  :let [flag (nth sec-bytes 0)]
  (= flag 4) (->S256Point (bytes->num (Arrays/copyOfRange sec-bytes 1 33))
                          (bytes->num (Arrays/copyOfRange sec-bytes 33 65)))
  :let [x (->FieldElement (bytes->num (Arrays/copyOfRange sec-bytes 1 33)) P),
        alpha (+ (expt x 3) B)
        beta (expt alpha (/ (inc P) 4))
        even_beta (if (even? (:num beta))
                    beta
                    (->FieldElement (- P (:num beta)) P))
        odd_beta (if (even? (:num beta))
                   (->FieldElement (- P (:num beta)) P)
                   beta)] 
  (= flag 2) (->S256Point x even_beta)
  :else (->S256Point x odd_beta))

(defn der ^bytes [{r :r s :s}]
  (let [rbin (.toByteArray (biginteger r)),
        rbin (concat [2 (count rbin)] rbin)
        sbin (.toByteArray (biginteger s))
        sbin (concat [2 (count sbin)] sbin)]
    (byte-array (concat [0x30 (+ (count rbin) (count sbin))]
                        rbin sbin))))
  
(defnc parse-der [^bytes der-bytes]
  :let [marker (nth der-bytes 0)]
  :do (assert (= marker 0x30) "Bad Signature")
  :let [length (nth der-bytes 1)]
  :do (assert (= (+ length 2) (count der-bytes)) "Bad Signature Length")
  :let [r-marker (nth der-bytes 2)]
  :do (assert (= r-marker 2) "Bad Signature")
  :let [r-length (int (nth der-bytes 3)),
        r (BigInteger. ^bytes (Arrays/copyOfRange der-bytes
                                                  (int 4)
                                                  (int (+ 4 r-length))))
        s-start (+ 4 r-length)
        s-marker (nth der-bytes s-start)]
  :do (assert (= s-marker 2) "Bad Signature")
  :let [s-length (nth der-bytes (inc s-start)),
        s (BigInteger. ^bytes (Arrays/copyOfRange
                               der-bytes
                               (int (+ s-start 2))
                               (int (+' s-start 2 s-length))))]
  :do (assert (= (count der-bytes) (+' 6 r-length s-length))
              "Signature too long")
  (->Signature r s))

;; Base 58 encoding

(def BASE58-ALPHABET "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
(def REVERSE-BASE58 (into {} (for [i (range 58)] [(nth BASE58-ALPHABET i) i])))

(defn encode-base58 [bs]
  (let [num-zeroes (count (take-while #{0} bs))
        prefix (repeat num-zeroes \1)]
    (loop [num (bytes->num bs), result ()]
      (cond
        (= num 0) (apply str (concat prefix result)),
        :let [digit (rem num 58)]
        (recur (quot num 58) (conj result (nth BASE58-ALPHABET digit)))))))

(defn encode-base58-checksum [bs]
  (encode-base58 (concat bs (take 4 (hash256 bs)))))

(defn decode-base58 ^bytes [s]
  (let [num (loop [num 0, s (seq s)]
              (if s
                (recur (+ (* num 58) (REVERSE-BASE58 (first s))) (next s))
                num))
        combined (num->bytes 25 num)
        checksum (bytes/slice combined 21 25)
        without-checksum (bytes/slice combined 0 21)]
    (cond
      (not= (vec (bytes/slice (hash256 without-checksum) 0 4))
            (vec checksum))
      (throw (ex-info "Bad address"
                      {:checksum (vec checksum),
                       :computed-checksum
                       (vec (bytes/slice (hash256 without-checksum) 0 4))}))
      :else (bytes/slice combined 1 21))))

;; Addresses

(defn hash-sec [point compressed?]
  (hash160 (sec point compressed?)))

(defnc point->address "options map :compressed? and :testnet?"
  ([point] (point->address point {}))
  ([point options]
   :let [{:keys [compressed? testnet?]}
         (merge {:compressed? true, :testnet? false} options),
         h160 (hash-sec point compressed?),
         prefix (if testnet? (byte 0x6f) (byte 0x00))]
   (encode-base58-checksum (byte-array (cons prefix h160)))))
   
(defnc address->hash [address]
  :let [num (loop [num 0 chars (seq address)]
              (if chars
                (recur (+ (* num 58) (get REVERSE-BASE58 (first chars)))
                       (next chars))
                num)),
        combined (num->bytes 25 num),
        checksum (take-last 4 combined)
        without-checksum (drop-last 4 combined)]
  :do (assert (= checksum (take 4 (hash256 (byte-array without-checksum)))) "Bad address")
  (byte-array (rest without-checksum)))

;; WIF format for private key

(defnc wif "Takes 256-bit secret number or PrivateKey record.
            options map :compressed? and :testnet?"
  ([secret] (wif secret {}))
  ([secret options]
   :let [{:keys [compressed? testnet?]}
         (merge {:compressed? true, :testnet? false} options),
         secret (if (instance? PrivateKey secret)
                  (:secret secret) secret)
         secret-bytes (num->bytes 32 secret),
         prefix (if testnet? [(unchecked-byte 0xef)] [(unchecked-byte 0x80)])
         suffix (if compressed? [(byte 0x01)] [])]
   (encode-base58-checksum (byte-array (concat prefix secret-bytes suffix)))))

;;; Printing utilities

;; Print secp256k1 points in hex notation
(defn hex64 [n] (format "0x%064x" (biginteger n)))
(defn pprint-FieldElement [{:keys [num prime] :as f}]
  (if (not= prime P) (pr f)
      (print (hex64 num))))
(. clojure.pprint/simple-dispatch addMethod FieldElement pprint-FieldElement)

