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
  [key iv data]
  {:pre [(= (count key) (count iv))]}
  (let [secret (SecretKeySpec. (byte-array (map ->byte key)) "AES")
        cipher (Cipher/getInstance "AES/ECB/NoPadding")
        blocks (partition-all (count key) data)
        decrypt (fn [[i c]] (fixed-xor i (.doFinal cipher (byte-array c))))]
    (.init cipher Cipher/DECRYPT_MODE secret)
    (into []
          (comp (map decrypt) cat)
          (zip (cons iv blocks) blocks))))

(defn aes-cbc-mode-decrypt-file
  "The Base64-encoded content in the file has been encrypted via AES-128 in CBC
  mode.  Decrypt it."
  [key iv file-path]
  (let [encrypted-data (base64file->bytes file-path)]
    (apply str (bytes->ascii (aes-cbc-mode-decrypt key iv encrypted-data)))))

(defn aes-cbc-mode-encryptor
  "Encrypts data using AES-128 in CBC mode. Returns a transducer with state,
  tracking the last ciphered data to use for the next xor."
  [key iv]
  {:pre [(= (count key) (count iv))]}
  (fn [rf]
    (let [secret (SecretKeySpec. (byte-array (map (comp unchecked-byte int) key)) "AES")
          cipher (Cipher/getInstance "AES/ECB/NoPadding")
          _ (.init cipher Cipher/ENCRYPT_MODE secret)
          iv-a (atom iv)]
      (fn
        ([] (rf))
        ([result] (rf result))
        ([result input]
         (swap! iv-a #(.doFinal cipher (byte-array (fixed-xor input %))))
         (rf result @iv-a))))))

(defn aes-cbc-mode-encrypt
  "Encrypted the data via AES-128 in CBC mode."
  [key iv data]
  {:pre [(= (count key) (count iv))]}
  (let [xf (comp
             (map (partial pkcs#7-padding (count key)))
             (aes-cbc-mode-encryptor key iv)
             cat)]
    (into [] xf (partition-all (count key) data))))

;;- set 2: challenge 11 -------------------------------------------------------

(defn aes-ecb-mode-encrypt
  "Encrypted the data via AES-128 in ECB mode."
  [key data]
  (let [secret (SecretKeySpec. (byte-array (map ->byte key)) "AES")
        cipher (Cipher/getInstance "AES/ECB/NoPadding")
        encrypt #(.doFinal cipher %)
        xf (comp
             (map (partial pkcs#7-padding (count key)))
             (map encrypt)
             cat)]
    (.init cipher Cipher/ENCRYPT_MODE secret)
    (into [] xf (partition-all (count key) data))))

(defn encryption-oracle [input]
  "Generates a random key and encrypts under it, randomly padding the data
  and picking a encryption mode (ecb/cbc)."
  (letfn [(take-rand [n]
           (take n (repeatedly #(rand-int 256))))]
    (let [key (take-rand 16)
          iv (take-rand 16)
          left-pad (take-rand (+ 5 (rand-int 6)))
          right-pad (take-rand (+ 5 (rand-int 6)))
          xf (comp cat
                   (map ->byte))
          data (into [] xf [left-pad input right-pad])
          mode ([:ecb :cbc] (rand-int 2))]
      (if (= mode :ecb)
        [:ecb (aes-ecb-mode-encrypt key data)]
        [:cbc (aes-cbc-mode-encrypt key iv data)]))))

;;- set 2: challenge 12 -------------------------------------------------------

(defn make-oracle-decryptor [unknown]
  "Encrypts buffers under ECB mode using a consistent but unknown key and pad
  the end with unknown bytes."
  (letfn [(take-rand [n]
            (take n (repeatedly #(rand-int 256))))]
    (let [key (take-rand 16)]
      (fn [input]
        (let [xf (comp cat (map ->byte))
              data (into [] xf [input unknown])]
      (aes-ecb-mode-encrypt key data))))))

(defn discover-block-size
  "Discover the block size of the cipher.  Create a bunch of encryptions and
  find the common divisor, will be the block size.  Since encoding requires
  fixed block size."
  [oracle]
  (let [make-input (fn [a n] (take n (repeat a)))
        input (partial make-input \A)
        encrypt #(oracle (input %))]
    (reduce gcd (map (comp count encrypt) (range 1 40)))))

(defn make-dictionary
  [oracle prefix]
  (let [all-bytes (map ->byte (range 256))
        first-block #(take 16 %)
        xf (comp (map (partial conj (vec prefix)))
                 (map oracle)
                 (map first-block))]
    (zipmap (into [] xf all-bytes)
            all-bytes)))

(defn byte-at-a-time-ecb-decryption [oracle block-size]
  "Create a transducer, return the found byte and keep state of the last found
  bytes to test against.
  1) Knowing the block size, craft an input block that is exactly 1 byte short.
     (for instance, if the block size is 8 bytes, make 'AAAAAAA').
  2) Make a dictionary of every possible last byte by feeding different strings
     to the oracle; for instance, 'AAAAAAAA', 'AAAAAAAB', 'AAAAAAAC',
     remembering the first block of each invocation.
  3) Match the output of the one-byte-short input to one of the entries in your
     dictionary. You've now discovered the first byte of unknown-string."
  (fn [rf]
    (letfn [(make-pad [n]
              (take n (repeat \A)))
            (get-block [b d]
              (drop (* b block-size) (take (* block-size (+ 1 b)) d)))]
      (let [tester (atom (vec (make-pad (- block-size 1))))]
        (fn
          ([] (rf))
          ([result] (rf result))
          ([result input]
           (let [b (quot input block-size)
                 n (rem input block-size)
                 pad-size (- block-size n 1)
                 dict (make-dictionary oracle @tester)
                 block (get-block b (oracle (make-pad pad-size)))
                 found (dict block)]
             (swap! tester #(let [[x & xs] %] (conj (vec xs) found)))
             (rf result found))))))))

;;-----------------------------------------------------------------------------

(defn -main
  ""
  [& args]
  (println "Nothing here."))
