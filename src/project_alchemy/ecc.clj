(ns project-alchemy.ecc)

(defprotocol FieldOps
  (add [x y])
  (sub [x y])
  (mul [x y])
  (div [x y])
  (expt [x power]))

(defrecord FieldElement [^BigInteger num ^BigInteger prime]
  FieldOps
  (add [x {^BigInteger num2 :num, ^BigInteger prime2 :prime}]
    (assert (= prime prime2))
    (FieldElement. (.mod (.add num num2) prime) prime))
  (sub [x {^BigInteger num2 :num, ^BigInteger prime2 :prime}]
    (assert (= prime prime2))
    (FieldElement. (.mod (.subtract num num2) prime) prime))
  (mul [x {^BigInteger num2 :num, ^BigInteger prime2 :prime}]
    (assert (= prime prime2))
    (FieldElement. (.mod (.multiply num num2) prime) prime))
  (div [x {^BigInteger num2 :num, ^BigInteger prime2 :prime}]
    (assert (= prime prime2))
    (FieldElement. (.mod (.multiply num (.modInverse num2 prime)) prime) prime))
  (expt [x power]
    (let [power (mod power (dec prime))]
      (FieldElement. (.modPow num (biginteger power) prime) prime))))

(defn ->FieldElement [num prime]
  (assert (and (<= 0 num) (< num prime)))
  (FieldElement. (biginteger num) (biginteger prime)))



