;;-----------------------------------------------------------------------------
;; The Matasano Crypto Challenges
;;-----------------------------------------------------------------------------

(ns cryptopals.core
  (:require [clojure.java.io :as io]
            [clojure.string :as string]
            [cryptopals.utils :refer :all])
  (:import
    [org.apache.commons.codec.binary Base64 Hex]
    [javax.crypto Cipher]
    [javax.crypto.spec SecretKeySpec])
  (:gen-class))

;;- set 2: challenge 1 --------------------------------------------------------

(defn pkcs#7-padding
  "Pad any block to a specific block length, by appending the number of bytes
  of padding to the end of the block."
  [block block-length]
  {:pre [(<= (count block) block-length)
         (<= block-length 256)]}
  (let [pad-size (- block-length (count block))
        padding (take pad-size (repeat (unchecked-byte pad-size)))]
    (into-array Byte/TYPE (concat block padding))))

;;-----------------------------------------------------------------------------

(defn -main
  ""
  [& args]
  (println "Nothing here."))
