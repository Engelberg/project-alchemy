(ns project-alchemy.ecc
  (:refer-clojure :exclude [+ - * / cond])
  (:require [clojure.math.numeric-tower :as nt]
            [better-cond.core :refer [cond defnc defnc-]])
  (:import java.util.Arrays
           java.security.SecureRandom
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

(declare S256Point? bytes32->num)
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
(def ^SecureRandom secure-random (SecureRandom.))
(defn rand-256 "Generates a random 256 bit number" ^BigInteger []
  (bytes32->num 256 secure-random))
(defnc rand-N "Generates a random number in Z_N" ^BigInteger []
  :let [i (rand-256)]
  (< i N) i
  (recur))

;; Second version of signing algo uses deterministic nonce
(defn hmac ^bytes [^bytes key ^bytes message]
  (let [hasher (Mac/getInstance "HmacSHA256"),
        _ (.init hasher (SecretKeySpec. key "HmacSHA256"))]
    (.doFinal hasher message)))

(defn num->bytes32 "Assumes number fits into 32 bytes"
  ^bytes [n]
  (let [a (.toByteArray (biginteger n)),
        l (count a),
        zeros (repeat (- 32 l) (byte 0))]
    ;; unsigned 32-byte num produces 33 bytes with leading 0,
    ;; which needs to be dropped
    (if (> l 32) 
      (byte-array (drop (- l 32) (seq a)))
      (byte-array (concat zeros a)))))

(defn bytes32->num "Interprets as unsigned 256-bit number"
  [^bytes bs]
  (BigInteger. (byte-array (into [0] bs))))

(defn deterministic-k "Generates a k from secret and z"
  [secret z]
  (let [k (byte-array 32 (byte 0))
        v (byte-array 32 (byte 1))
        z (if (> z N) (- z N) z)
        z-bytes (num->bytes32 z)
        secret-bytes (num->bytes32 secret)
        k (hmac k (byte-array (concat v [0] secret-bytes z-bytes)))
        v (hmac k v)
        k (hmac k (byte-array (concat v [1] secret-bytes z-bytes)))
        v (hmac k v)]
    (loop [k k v v]
      (cond
        :let [v (hmac k v)
              candidate (bytes32->num v)]
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
      (concat [4] (num->bytes32 (:num x)) (num->bytes32 (:num y))))
     (byte-array
      (concat (if (even? (:num y)) [2] [3]) (num->bytes32 (:num x)))))))

(defnc parse-sec "Parses SEC bytes" [^bytes sec-bytes]
  :let [flag (nth sec-bytes 0)]
  (= flag 4) (->S256Point (bytes32->num (Arrays/copyOfRange sec-bytes 1 33))
                          (bytes32->num (Arrays/copyOfRange sec-bytes 33 65)))
  :let [x (->FieldElement (bytes32->num (Arrays/copyOfRange sec-bytes 1 33)) P),
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










;;; Printing utilities

;; Print secp256k1 points in hex notation
(defn hex [n] (format "0x%064x" (biginteger n)))
(defn pprint-FieldElement [{:keys [num prime] :as f}]
  (if (not= prime P) (pr f)
      (print (hex num))))
(. clojure.pprint/simple-dispatch addMethod FieldElement pprint-FieldElement)

(defn- left0
  "Adds 0 on the left of a single-digit string, since a byte should always be two hex digits"
  [s]
  (if (= (count s) 1) (str \0 s) s))

(defn hex-encode
  "Converts bytes to string of hexadecimal numbers"
  [bs]
  (apply str (map (comp left0 #(Integer/toUnsignedString % 16) #(Byte/toUnsignedInt %)) bs)))

