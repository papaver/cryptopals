;;-----------------------------------------------------------------------------
;; The Matasano Crypto Challenges
;;-----------------------------------------------------------------------------

(ns cryptopals.core
  (:require [clojure.java.io :as io]
            [clojure.string :as string]
            [cryptopals.set1 :refer [fixed-xor]]
            [cryptopals.utils :refer :all])
  (:import
    [org.apache.commons.codec.binary Base64 Hex]
    [javax.crypto Cipher]
    [javax.crypto.spec SecretKeySpec])
  (:gen-class))

;;- set 2: challenge 9 --------------------------------------------------------

(defn pkcs#7-padding
  "Pad any block to a specific block length, by appending the number of bytes
  of padding to the end of the block."
  [block-length block]
  {:pre [(<= (count block) block-length)
         (<= block-length 256)]}
  (let [pad-size (- block-length (count block))
        padding (take pad-size (repeat (unchecked-byte pad-size)))]
    (into-array Byte/TYPE (concat block padding))))

;;- set 2: challenge 10 -------------------------------------------------------

(defn aes-cbc-mode-decrypt
  "The data has been encrypted via AES-128 in CBC mode.  Decrypt it."
  [data key iv]
  {:pre [(= (count key) (count iv))]}
  (let [secret (SecretKeySpec. (byte-array (map byte key)) "AES")
        cipher (Cipher/getInstance "AES/ECB/NoPadding")
        blocks (partition (count key) data)
        decrypt (fn [[i c]] (fixed-xor i (.doFinal cipher (byte-array c))))]
    (.init cipher Cipher/DECRYPT_MODE secret)
    (into []
          (comp (map decrypt) cat)
          (zip (cons iv blocks) blocks))))

(defn aes-cbc-mode-decrypt-file
  "The Base64-encoded content in the file has been encrypted via AES-128 in CBC
  mode.  Decrypt it."
  [file-path key iv]
  (let [encrypted-data (base64file->bytes file-path)]
    (apply str (bytes->ascii (aes-cbc-mode-decrypt encrypted-data key iv)))))

(defn aes-cbc-mode-encryptor
  "Encrypts data using AES-128 in CBC mode. Returns a transducer with state,
  tracking the last ciphered data to use for the next xor."
  ([key iv]
   (fn [rf]
     (let [secret (SecretKeySpec. (byte-array (map byte key)) "AES")
           cipher (Cipher/getInstance "AES/ECB/NoPadding")
           _ (.init cipher Cipher/ENCRYPT_MODE secret)
           iv-a (atom iv)]
       (fn
         ([] (rf))
         ([result] (rf result))
         ([result input]
          (swap! iv-a #(.doFinal cipher (byte-array (fixed-xor input %))))
          (rf result @iv-a)))))))

(defn aes-cbc-mode-encrypt
  "Encrypted the data via AES-128 in CBC mode."
  [data key iv]
  {:pre [(= (count key) (count iv))]}
  (let [xf (comp
             (map (partial pkcs#7-padding (count key)))
             (aes-cbc-mode-encryptor key iv)
             cat)]
    (into [] xf (partition (count key) data))))

;;-----------------------------------------------------------------------------

(defn -main
  ""
  [& args]
  (println "Nothing here."))
