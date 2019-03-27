(ns project-alchemy.ecc
  (:refer-clojure :exclude [+ - * / cond])
  (:require [clojure.math.numeric-tower :as nt]
            [better-cond.core :refer [cond defnc defnc-]]))

(def A 0)
(def B 7)
(def P (clojure.core/- (nt/expt 2 256) (nt/expt 2 32) 977))
(def N 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141)
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

(defrecord S256Point [x y]
  FieldOps
  (zero [p] (S256Point. nil nil))
  (+ [p1 {x2 :x y2 :y :as p2}]
    (cond
      (nil? x) p2
      (nil? x2) p1
      (and (= x x2) (not= y y2)) (S256Point. nil nil)
      (= p1 p2) (if (= y (zero x)) (S256Point. nil nil)
                    (let [s (/ (* 3 (expt x 2)) (* 2 y)),
                          x3 (- (expt s 2) (* 2 x))
                          y3 (- (* s (- x x3)) y)]
                      (S256Point. x3 y3)))
      :else (let [s (/ (- y2 y) (- x2 x)),
                  x3 (- (- (expt s 2) x) x2),
                  y3 (- (* s (- x x3)) y)]
              (S256Point. x3 y3)))))

(defn ->S256Point [x y]
  (let [x (->FieldElement x P), y (->FieldElement y P) A (->FieldElement A P), B (->FieldElement B P)]
    (assert (valid-point? x y A B) "Point not on curve")
    (S256Point. x y)))

(defn S256Point? [p] (instance? S256Point p))

(def G (->S256Point
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8))

(defn pprint-256point [p]
  (let [^BigInteger x (:num (:x p)),
        ^BigInteger y (:num (:y p))]
    (if (nil? x) (println "S256Point(infinity)")
        (do (println "S256Point(")
            (println (str " 0x" (.toString x 16) ","))
            (println (str " 0x" (.toString y 16) ")"))))))

(. clojure.pprint/simple-dispatch addMethod S256Point pprint-256point)
