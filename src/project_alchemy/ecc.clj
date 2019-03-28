(ns project-alchemy.ecc
  (:refer-clojure :exclude [+ - * / cond])
  (:require [clojure.math.numeric-tower :as nt]
            [better-cond.core :refer [cond defnc defnc-]])
  (:import java.security.SecureRandom
           javax.crypto.Mac
           javax.crypto.spec.SecretKeySpec))

(def P (clojure.core/- (nt/expt 2 256) (nt/expt 2 32) 977))
(def N (biginteger 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141))
(declare S256Point?)

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
  (+ [x y] (clojure.core/+ x y))
  (- [x y] (clojure.core/- x y))
  (* [x y] (cond
             (number? y) (clojure.core/* x y)
             (S256Point? y) (scalar-multiply (mod x N) y)
             :else (scalar-multiply x y)))
  (/ [x y] (clojure.core// x y))
  (zero [x] 0)
  (expt [x exponent] (nt/expt x exponent)))

(defrecord FieldElement [^BigInteger num ^BigInteger prime]
  FieldOps
  (+ [x {^BigInteger num2 :num, ^BigInteger prime2 :prime}]
    (assert (= prime prime2) "Cannot add number from two different fields")
    (FieldElement. (.mod (.add num num2) prime) prime))
  (- [x {^BigInteger num2 :num, ^BigInteger prime2 :prime}]
    (assert (= prime prime2) "Cannot subtract number from two different fields")
    (FieldElement. (.mod (.subtract num num2) prime) prime))
  (* [x {^BigInteger num2 :num, ^BigInteger prime2 :prime}]
    (assert (= prime prime2) "Cannot multiply number from two different fields")
    (FieldElement. (.mod (.multiply num num2) prime) prime))
  (/ [x {^BigInteger num2 :num, ^BigInteger prime2 :prime}]
    (assert (= prime prime2) "Cannot divide number from two different fields")
    (FieldElement. (.mod (.multiply num (.modInverse num2 prime)) prime) prime))
  (zero [x] (FieldElement. BigInteger/ZERO prime))
  (expt [x exponent]
    (let [exponent (mod exponent (dec prime))]
      (FieldElement. (.modPow num (biginteger exponent) prime) prime))))

(defn ->FieldElement [num prime]
  (assert (and (<= 0 num) (< num prime)))
  (FieldElement. (biginteger num) (biginteger prime)))

(defn hex [n] (format "0x%064x" n))
(defn pprint-FieldElement [{:keys [num prime] :as f}]
  (if (not= prime P) (pr f)
      (print (hex num))))
(. clojure.pprint/simple-dispatch addMethod FieldElement pprint-FieldElement)

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

(defn ->S256Point [x y]
  (let [x (when x (->FieldElement x P)), y (when y (->FieldElement y P))]
    (assert (valid-point? x y A B) "Point not on curve")
    (Point. x y A B)))

(defn S256Point? [{:keys [a b]}] (and (= a A) (= b B)))

(def G (->S256Point
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8))

(defrecord Signature [^BigInteger r ^BigInteger s])

(defn ->Signature [r s]
  (Signature. (biginteger r) (biginteger s)))

(defnc verify-signature
  "Takes a public-key (point on secp256k1 curve), z (256-bit hash of some data), and a signature (with BigInteger r and s)"
  [public-key z {:keys [^BigInteger r ^BigInteger s]}]
  :let [s-inv (.modInverse s N),
        u (mod (* z s-inv) N),
        v (mod (* r s-inv) N),
        total (+ (* u G) (* v public-key))]
  (= (:num (:x total)) r))

;; PrivateKey tracks a secret 256-bit number and the corresponding public-key,
;; which is a point on the secp256k1 curve
(defrecord PrivateKey [secret point])

(defn ->PrivateKey [secret]
  (PrivateKey. (biginteger secret) (* secret G)))

(def secure-random (SecureRandom.))
(defn rand-256 "Generates a random 256 bit number" ^BigInteger []
  (BigInteger. 256 secure-random))
(defnc rand-N "Generates a random number in Z_N" ^BigInteger []
  :let [i (rand-256)]
  (< i N) i
  (recur))

(defn hmac ^bytes [^bytes key ^bytes message]
  (let [hasher (Mac/getInstance "HmacSHA256"),
        _ (.init hasher (SecretKeySpec. key "HmacSHA256"))]
    (.doFinal hasher message)))

(defn biginteger->32bytes "Assumes biginteger fits into 32 bytes"
  ^bytes [^BigInteger n]
  (let [a (.toByteArray n),
        l (count a),
        zeros (repeat (- 32 l) (byte 0))]
    (byte-array (concat zeros a))))

(defn deterministic-k "Generates a k from secret and z"
  ^BigInteger [^BigInteger secret ^BigInteger z]
  (let [k (byte-array 32 (byte 0))
        v (byte-array 32 (byte 1))
        z (if (> z N) (- z N) z)
        z-bytes (biginteger->32bytes z)
        secret-bytes (biginteger->32bytes secret)
        k (hmac k (byte-array (concat v [0] secret-bytes z-bytes)))
        v (hmac k v)
        k (hmac k (byte-array (concat v [1] secret-bytes z-bytes)))
        v (hmac k v)]
    (loop [k k v v]
      (cond
        :let [v (hmac k v)
              candidate (BigInteger. v)]
        (and (<= 1 candidate) (< candidate N)) candidate
        :let [k (hmac k (byte-array (concat v [0]))),
              v (hmac k v)]
        (recur k v)))))

(defnc sign "Takes a PrivateKey and a 256-bit hash, produces Signature"
  [{:keys [secret point]} z]
  :let [k (deterministic-k secret z) ;; (rand-N),
        r (-> (* k G) :x :num),
        k-inv (.modInverse k N),
        s (mod (* (+ z (* r secret)) k-inv) N)]
  (> s (quot N 2)) (->Signature r (- N s))
  :else (->Signature r s))

;; Printing utilities

(defn- left0
  "Adds 0 on the left of a single-digit string, since a byte should always be two hex digits"
  [s]
  (if (= (count s) 1) (str \0 s) s))

(defn hex-encode
  "Converts bytes to string of hexadecimal numbers"
  [bs]
  (apply str (map (comp left0 #(Integer/toUnsignedString % 16) #(Byte/toUnsignedInt %)) bs)))

