(ns project-alchemy.script
  (:require [project-alchemy.helper :refer [read-bytes read-varint encode-varint le-bytes->num le-num->bytes hash256]])
  (:import java.io.InputStream))

(defn parse-script-sig [^InputStream stream])

(defn serialize-script-sig ^bytes [script-sig])

(defn parse-script-pubkey [^InputStream stream])

(defn serialize-script-pubkey ^bytes [script-pubkey])
