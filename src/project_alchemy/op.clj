(ns project-alchemy.op
  (:refer-clojure :exclude [cond pop peek])
  (:require [project-alchemy.helper :refer [read-bytes read-varint encode-varint le-bytes->num le-num->bytes hash160 hash256 unsigned-byte]]
            [better-cond.core :refer [defnc defnc- cond]]
            [clojure.math.numeric-tower :as m]
            [project-alchemy.ecc :as ecc]
            [buddy.core.codecs :refer :all]
            [buddy.core.hash :as h])  
  (:import java.util.Stack java.util.Arrays))

(defn pop
  ([^Stack stack] (.pop stack))
  ([^Stack stack n] (for [_ (range n)] (.pop stack))))
(defn push [^Stack stack e] (.push stack e) true)
(defn peek
  ([^Stack stack] (.peek stack))
  ([^Stack stack n]
   (let [top (pop stack n)]
     (doseq [item (rseq top)] (push stack item)))))
(defn make-stack ^Stack [v]
  (let [s (Stack.)]
    (doseq [e v] (push s e))
    s))

(defnc encode-num [num]
  (= num 0) (byte-array [])
  (byte-array (loop [result [] abs-num (m/abs num)]
                (cond (= abs-num 0) (cond
                                      :let [last-num (clojure.core/peek result)]
                                      (not (zero? (bit-and last-num 0x80)))
                                      (if (neg? num)
                                        (conj result 0x80)
                                        (conj result 0))
                                      (neg? num) (conj (clojure.core/pop result)
                                                       (bit-or last-num 0x80))
                                      result)
                      (recur (conj result (bit-and abs-num 0xff))
                             (unsigned-bit-shift-right abs-num 8))))))

(defnc decode-num [^bytes bs]
  :let [s (rseq (vec bs))]
  (empty? s) 0
  :let [[negative? result]
        (if (not (zero? (bit-and (first s) 0x80)))
          [true (bit-and (first s) 0x7f)]
          [false (unsigned-byte (first s))])]
  (loop [s (next s), result result]
    (cond
      s (recur (next s) (+ (bit-shift-left result 8) (unsigned-byte (first s))))
      negative? (- result)
      :else result)))


(defnc op-0 [stack]
  (push stack (encode-num 0)))

(defnc op-1 [stack]
  (push stack (encode-num 1)))

(defnc op-1negate [stack]
  (push stack (encode-num -1)))

(defnc op-2 [stack]
  (push stack (encode-num 2)))

(defnc op-3 [stack]
  (push stack (encode-num 3)))

(defnc op-4 [stack]
  (push stack (encode-num 4)))

(defnc op-5 [stack]
  (push stack (encode-num 5)))

(defnc op-6 [stack]
  (push stack (encode-num 6)))

(defnc op-7 [stack]
  (push stack (encode-num 7)))

(defnc op-8 [stack]
  (push stack (encode-num 8)))

(defnc op-9 [stack]
  (push stack (encode-num 9)))

(defnc op-10 [stack]
  (push stack (encode-num 10)))

(defnc op-11 [stack]
  (push stack (encode-num 11)))

(defnc op-12 [stack]
  (push stack (encode-num 12)))

(defnc op-13 [stack]
  (push stack (encode-num 13)))

(defnc op-14 [stack]
  (push stack (encode-num 14)))

(defnc op-15 [stack]
  (push stack (encode-num 15)))

(defnc op-16 [stack]
  (push stack (encode-num 16)))

(defnc op-nop [stack] true)

(defnc op-if "Takes stack and atom with items to manipulate" [stack a-items]
  (< (count stack) 1) false
  :let [[items true-items false-items]
        (loop [items (seq @a-items) true-items [] false-items [] current-array true
               num-endifs-needed 1]
          (if-not items
            [false true-items false-items] ;; false signals we failed to find endif
            (cond
              :let [item (first items), items (next items)]
              (contains? #{99 100} item)
              (if current-array
                (recur items (conj true-items item) false-items current-array (inc num-endifs-needed))
                (recur items true-items (conj false-items item) current-array (inc num-endifs-needed)))
              
              (and (= num-endifs-needed 1) (= item 103))
              (recur items true-items false-items false num-endifs-needed)
              
              (= item 104)
              (cond
                (= num-endifs-needed 1) [items true-items false-items]
                current-array (recur items (conj true-items item) false-items current-array (dec num-endifs-needed))
                :else (recur items true-items (conj false-items item) current-array (dec num-endifs-needed)))
              
              current-array (recur items (conj true-items item) false-items current-array num-endifs-needed)
              :else (recur items true-items (conj false-items item) current-array num-endifs-needed))))]
  
  (false? items) false
  :let [element (pop stack)]
  :do (if (= 0 (decode-num element))
        (reset! a-items (concat false-items items))
        (reset! a-items (concat true-items items)))
  true)

(defnc op-notif [stack a-items]
  (< (count stack) 1) false
  :let [[items true-items false-items]
        (loop [items (seq @a-items) true-items [] false-items [] current-array true
               num-endifs-needed 1]
          (if-not items
            [false true-items false-items]
            (cond
              :let [item (first items), items (next items)]
              (contains? #{99 100} item)
              (if current-array
                (recur items (conj true-items item) false-items current-array (inc num-endifs-needed))
                (recur items true-items (conj false-items item) current-array (inc num-endifs-needed)))
              
              (and (= num-endifs-needed 1) (= item 103))
              (recur items true-items false-items false num-endifs-needed)
              
              (= item 104)
              (cond
                (= num-endifs-needed 1) [items true-items false-items]
                current-array (recur items (conj true-items item) false-items current-array (dec num-endifs-needed))
                :else (recur items true-items (conj false-items item) current-array (dec num-endifs-needed)))
              
              current-array (recur items (conj true-items item) false-items current-array num-endifs-needed)
              :else (recur items true-items (conj false-items item) current-array num-endifs-needed))))]
  
  (false? items) false
  :let [element (pop stack)]
  :do (if (= 0 (decode-num element))
        (reset! a-items (concat true-items items))
        (reset! a-items (concat false-items items)))
  true)

(defnc op-verify [stack]
  (< (count stack) 1) false
  (= 0 (decode-num (pop stack))) false
  true)

(defn op-return [stack] false)

(defnc op-toaltstack [stack altstack]
  (< (count stack) 1) false
  (push altstack (pop stack)))

(defnc op-fromaltstack [stack altstack]
  (< (count stack) 1) false
  (push stack (pop altstack)))

(defnc op-2drop [stack]
  (< (count stack) 2) false
  :do (pop stack)
  :do (pop stack)
  true)

(defnc op-dup [stack]
  (< (count stack) 1) false
  (push stack (peek stack)))

(defnc op-2dup [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (peek stack 2)]
  (do (push stack t2) (push stack t1)))

(defnc op-3dup [stack]
  (< (count stack) 3) false
  :let [[t1 t2 t3] (peek stack 3)]
  (do (push stack t3) (push stack t2) (push stack t1)))

(defnc op-2over [stack]
  (< (count stack) 4) false
  :let [[t1 t2 t3 t4] (peek stack 4)]
  (do (push stack t4) (push stack t3)))

(defnc op-2rot [stack]
  (< (count stack) 6) false
  :let [[t1 t2 t3 t4 t5 t6] (pop stack 6)]
  (do (push stack t4) (push stack t3) (push stack t2) (push stack t1)
      (push stack t6) (push stack t5)))

(defnc op-2swap [stack]
  (< (count stack) 4) false
  :let [[t1 t2 t3 t4] (pop stack 4)]
  (do (push stack t2) (push stack t1) (push stack t4) (push stack t3)))

(defnc op-ifdup [stack]
  (< (count stack) 1) false
  (not= 0 (decode-num (peek stack))) (op-dup stack)
  true)

(defnc op-depth [stack]
  (push stack (encode-num (count stack))))

(defnc op-drop [stack]
  (< (count stack) 1) false
  (do (pop stack) true))

(defnc op-nip [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (pop stack 2)]
  (push stack t2))

(defnc op-over [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (peek stack 2)]
  (push stack t2))

(defnc op-pick [stack]
  (< (count stack) 1) false
  :let [n (decode-num (pop stack))]
  (< (count stack) (inc n)) false
  (push stack (last (peek stack (inc n)))))

(defnc op-roll [stack]
  (< (count stack) 1) false
  :let [n (decode-num (pop stack))]
  (< (count stack) (inc n)) false
  (= n 0) true
  :let [top-n (rseq (pop stack (inc n))),
        item (first top-n)]
  (do (doseq [i (rest top-n)] (push stack i)) (push stack item)))

(defnc op-rot [stack]
  (< (count stack) 3) false
  :let [[t1 t2 t3] (pop stack 3)]
  (do (push stack t2) (push stack t1) (push stack t3)))

(defnc op-swap [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (pop stack 2)]
  (do (push stack t1) (push stack t2)))

(defnc op-tuck [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (pop stack 2)]
  (do (push stack t1) (push stack t2) (push stack t1)))

(defnc op-size [stack]
  (< (count stack) 1) false
  (push stack (encode-num (count (peek stack)))))

(defnc op-equal [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (pop stack 2)]
  (= t1 t2) (push stack (encode-num 1))
  :else (push stack (encode-num 0)))

(defnc op-equalverify [stack]
  (and (op-equal stack) (op-verify stack)))

(defnc op-1add [stack]
  (< (count stack) 1) false
  (push stack (encode-num (inc (decode-num (pop stack))))))

(defnc op-1sub [stack]
  (< (count stack) 1) false
  (push stack (encode-num (dec (decode-num (pop stack))))))

(defnc op-negate [stack]
  (< (count stack) 1) false
  (push stack (encode-num (- (decode-num (pop stack))))))

(defnc op-abs [stack]
  (< (count stack) 1) false
  (push stack (encode-num (m/abs (decode-num (pop stack))))))

(defnc op-not [stack]
  (< (count stack) 1) false
  (= 0 (decode-num (pop stack))) (op-1 stack)
  :else (op-0 stack))

(defnc op-0notequal [stack]
  (< (count stack) 1) false
  (= 0 (decode-num (pop stack))) (op-0 stack)
  :else (op-1 stack))

(defnc op-add [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (push stack (encode-num (+ t1 t2))))

(defnc op-sub [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (push stack (encode-num (- t1 t2))))

(defnc op-mul [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (push stack (encode-num (* t1 t2))))

(defnc op-booland [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (and (not (zero? t1)) (not (zero? t2))) (op-1 stack)
  :else (op-0 stack))

(defnc op-boolor [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (or (not (zero? t1)) (not (zero? t2))) (op-1 stack)
  :else (op-0 stack))

(defnc op-numequal [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (= t1 t2) (op-1 stack)
  :else (op-0 stack))

(defnc op-numequalverify [stack]
  (and (op-numequal stack) (op-verify stack)))

(defnc op-numnotequal [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (not= t1 t2) (op-1 stack)
  :else (op-0 stack))

(defnc op-lessthan [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (< t1 t2) (op-1 stack)
  :else (op-0 stack))

(defnc op-greaterthan [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (> t1 t2) (op-1 stack)
  :else (op-0 stack))

(defnc op-lessthanorequal [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (<= t1 t2) (op-1 stack)
  :else (op-0 stack))

(defnc op-greaterthanorequal [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (>= t1 t2) (op-1 stack)
  :else (op-0 stack))

(defnc op-min [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (< t1 t2) (push stack t1)
  :else (push stack t2))

(defnc op-max [stack]
  (< (count stack) 2) false
  :let [[t1 t2] (map decode-num (pop stack 2))]
  (> t1 t2) (push stack t1)
  :else (push stack t2))

(defnc op-within [stack]
  (< (count stack) 3) false
  :let [[maximum minimum element] (pop stack 3)]
  (and (>= minimum element) (< element maximum)) (op-1 stack)
  :else (op-0 stack))

(defnc op-ripemd160 [stack]
  (< (count stack) 1) false
  (push stack (h/ripemd160 (pop stack))))

(defnc op-sha1 [stack]
  (< (count stack) 1) false
  (push stack (h/sha1 (pop stack))))

(defnc op-sha256 [stack]
  (< (count stack) 1) false
  (push stack (h/sha256 (pop stack))))

(defnc op-hash256 [stack]
  (< (count stack) 1) false
  (push stack (hash256 (pop stack))))

(defnc op-hash160 [stack]
  (< (count stack) 1) false
  (push stack (hash160 (pop stack))))

(defnc op-checksig [stack z]
  :let [[sec-bytes der-bytes] (pop stack 2)
        der-bytes (Arrays/copyOfRange der-bytes
                                      (int 0)
                                      (int (dec (count der-bytes))))
        pubkey (ecc/parse-sec sec-bytes),
        signature (ecc/parse-der der-bytes)]
  (ecc/verify-signature pubkey z signature) (op-1 stack)
  :else (op-0 stack))

(defnc op-checksigverify [stack z]
  (and (op-checksig stack z) (op-verify stack)))

(defnc op-checkmultisig [stack z]
  (throw (UnsupportedOperationException.)))

(defnc op-checkmultisigverify [stack z]
  (throw (UnsupportedOperationException.)))

(defnc op-checklocktimeverify [stack locktime sequence]
  (= sequence 0xffffffff) false
  (< (count stack) 1) false
  :let [element (decode-num (peek stack))]
  (< element 0) false
  (and (< element 500000000) (> locktime  500000000)) false
  (< locktime element) false
  :else true)

(def exp231 (bit-shift-left 1 31))

(defnc op-checksequenceverify [stack version sequence]
  (= (bit-and sequence exp231) exp231) false
  (< (count stack) 1) false
  :let [element (decode-num (peek stack))]
  (< element 0) false
  (= (bit-and element exp231) exp231)
  (cond (< version 2) false
        (= (bit-and sequence exp231) exp231) false
        (not= (bit-and element (bit-shift-left 1 22))
              (bit-and sequence (bit-shift-left 1 22))) false
        (> (bit-and element 0xffff) (bit-and sequence 0xffff)) false)
  true)

(def op-code-functions
  { 0 op-0,
   79 op-1negate,
   81 op-1,
   82 op-2,
   83 op-3,
   84 op-4,
   85 op-5,
   86 op-6,
   87 op-7,
   88 op-8,
   89 op-9,
   90 op-10,
   91 op-11,
   92 op-12,
   93 op-13,
   94 op-14,
   95 op-15,
   96 op-16,
   97 op-nop,
   99 op-if,
   100 op-notif,
   105 op-verify,
   106 op-return,
   107 op-toaltstack,
   108 op-fromaltstack,
   109 op-2drop,
   110 op-2dup,
   111 op-3dup,
   112 op-2over,
   113 op-2rot,
   114 op-2swap,
   115 op-ifdup,
   116 op-depth,
   117 op-drop,
   118 op-dup,
   119 op-nip,
   120 op-over,
   121 op-pick,
   122 op-roll,
   123 op-rot,
   124 op-swap,
   125 op-tuck,
   130 op-size,
   135 op-equal,
   136 op-equalverify,
   139 op-1add,
   140 op-1sub,
   143 op-negate,
   144 op-abs,
   145 op-not,
   146 op-0notequal,
   147 op-add,
   148 op-sub,
   149 op-mul,
   154 op-booland,
   155 op-boolor,
   156 op-numequal,
   157 op-numequalverify,
   158 op-numnotequal,
   159 op-lessthan,
   160 op-greaterthan,
   161 op-lessthanorequal,
   162 op-greaterthanorequal,
   163 op-min,
   164 op-max,
   165 op-within,
   166 op-ripemd160,
   167 op-sha1,
   168 op-sha256,
   169 op-hash160,
   170 op-hash256,
   172 op-checksig,
   173 op-checksigverify,
   174 op-checkmultisig,
   175 op-checkmultisigverify,
   176 op-nop,
   177 op-checklocktimeverify,
   178 op-checksequenceverify,
   179 op-nop,
   180 op-nop,
   181 op-nop,
   182 op-nop,
   183 op-nop,
   184 op-nop,
   185 op-nop,
   })

(def op-code-names
  {  0 "OP_0",
    76 "OP_PUSHDATA1",
    77 "OP_PUSHDATA2",
    78 "OP_PUSHDATA4",
    79 "OP_1NEGATE",
    81 "OP_1",
    82 "OP_2",
    83 "OP_3",
    84 "OP_4",
    85 "OP_5",
    86 "OP_6",
    87 "OP_7",
    88 "OP_8",
    89 "OP_9",
    90 "OP_10",
    91 "OP_11",
    92 "OP_12",
    93 "OP_13",
    94 "OP_14",
    95 "OP_15",
    96 "OP_16",
    97 "OP_NOP",
    99 "OP_IF",
    100 "OP_NOTIF",
    103 "OP_ELSE",
    104 "OP_ENDIF",
    105 "OP_VERIFY",
    106 "OP_RETURN",
    107 "OP_TOALTSTACK",
    108 "OP_FROMALTSTACK",
    109 "OP_2DROP",
    110 "OP_2DUP",
    111 "OP_3DUP",
    112 "OP_2OVER",
    113 "OP_2ROT",
    114 "OP_2SWAP",
    115 "OP_IFDUP",
    116 "OP_DEPTH",
    117 "OP_DROP",
    118 "OP_DUP",
    119 "OP_NIP",
    120 "OP_OVER",
    121 "OP_PICK",
    122 "OP_ROLL",
    123 "OP_ROT",
    124 "OP_SWAP",
    125 "OP_TUCK",
    130 "OP_SIZE",
    135 "OP_EQUAL",
    136 "OP_EQUALVERIFY",
    139 "OP_1ADD",
    140 "OP_1SUB",
    143 "OP_NEGATE",
    144 "OP_ABS",
    145 "OP_NOT",
    146 "OP_0NOTEQUAL",
    147 "OP_ADD",
    148 "OP_SUB",
    149 "OP_MUL",
    154 "OP_BOOLAND",
    155 "OP_BOOLOR",
    156 "OP_NUMEQUAL",
    157 "OP_NUMEQUALVERIFY",
    158 "OP_NUMNOTEQUAL",
    159 "OP_LESSTHAN",
    160 "OP_GREATERTHAN",
    161 "OP_LESSTHANOREQUAL",
    162 "OP_GREATERTHANOREQUAL",
    163 "OP_MIN",
    164 "OP_MAX",
    165 "OP_WITHIN",
    166 "OP_RIPEMD160",
    167 "OP_SHA1",
    168 "OP_SHA256",
    169 "OP_HASH160",
    170 "OP_HASH256",
    171 "OP_CODESEPARATOR",
    172 "OP_CHECKSIG",
    173 "OP_CHECKSIGVERIFY",
    174 "OP_CHECKMULTISIG",
    175 "OP_CHECKMULTISIGVERIFY",
    176 "OP_NOP1",
    177 "OP_CHECKLOCKTIMEVERIFY",
    178 "OP_CHECKSEQUENCEVERIFY",
    179 "OP_NOP4",
    180 "OP_NOP5",
    181 "OP_NOP6",
    182 "OP_NOP7",
    183 "OP_NOP8",
    184 "OP_NOP9",
    185 "OP_NOP10",
})
