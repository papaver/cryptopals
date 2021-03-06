;;-----------------------------------------------------------------------------
;; The Matasano Crypto Challenges: Set 1: Basics
;;-----------------------------------------------------------------------------

(ns cryptopals.set1
  (:require [clojure.java.io :as io]
            [clojure.string :as string]
            [cryptopals.utils :refer :all])
  (:import
    [org.apache.commons.codec.binary Base64]
    [javax.crypto Cipher]
    [javax.crypto.spec SecretKeySpec]))

;;- set 1: challenge 1 --------------------------------------------------------

(defn hex->base64
  "Convert string hex to base64."
  [hex]
  (Base64/encodeBase64String (hex->bytes hex)))

;;- set 1: challenge 2 --------------------------------------------------------

(defn fixed-xor
  "Takes two equal-length buffers and produces their XOR combination."
  [x y]
  {:pre [(= (count x) (count y))]}
  (map (partial apply bit-xor) (zip x y)))

(defn fixed-xor-hex
  "Takes two equal-length buffers and produces their XOR combination."
  [hex-x hex-y]
  (let [bytes-x (hex->bytes hex-x)
        bytes-y (hex->bytes hex-y)]
    (bytes->hex (byte-array (fixed-xor bytes-x bytes-y)))))

;;- set 1: challenge 3 --------------------------------------------------------

(defn a-z?
  "Character is between a and z."
  [c]
  (let [x (int c)]
    (and (<= 97 x) (<= x 122))))

(defn letter-frequencies
  "Calculate frequencies of english letters in string."
  [s]
  (let [ls (filter a-z? (string/lower-case s))]
    (frequencies ls)))

(def en-letter-frequencies
  "English language letter frequencies.
   reference: https://en.wikipedia.org/wiki/Letter_frequency"
  {\a 0.08167 \b 0.01492 \c 0.02782 \d 0.04253 \e 0.12702 \f 0.02228 \g 0.02015
   \h 0.06094 \i 0.06966 \j 0.00153 \k 0.00772 \l 0.04025 \m 0.02406 \n 0.06749
   \o 0.07507 \p 0.01929 \q 0.00095 \r 0.05987 \s 0.06327 \t 0.09056 \u 0.02758
   \v 0.00978 \w 0.02360 \x 0.00150 \y 0.01974 \z 0.00074})

(defn non-english-penelty
  "Penalize all characters not within the normal alphabet and punctuation."
  [s]
  (letfn [(bad-char [c]
            (not (re-matches #"[a-zA-Z0-9?!,.'\n\- ]+" (str c))))]
    (reduce #(+ %1 (if (bad-char %2) 10.0 0.0)) 0 s)))

(defn is-english?-score
  "Use chi-squared testing to score a string as english."
  [s]
  (try (let [s-freqs (letter-frequencies s)
             s-len (reduce + (vals s-freqs))
             en-freq-err (fn [k v] (sqr-err (get s-freqs k 0) (* s-len v)))]
         (+ (reduce-kv #(+ %1 (en-freq-err %2 %3)) 0 en-letter-frequencies)
            (non-english-penelty s)))
       (catch Exception e nil)))

(defn single-byte-xor-cipher
  "Find the single key xor and decrypt the message."
  [input]
  (letfn [(repeat-key [k]
            (take (count input) (repeat k)))
          (score-test [s]
            {:msg (apply str s)
             :score (is-english?-score s)})
          (merge-keys [scores test-keys]
            (map (fn [[s k]] (assoc s :key k)) (zip scores test-keys)))]
    (let [xf (comp (map repeat-key)
                   (map (partial fixed-xor input))
                   (map bytes->ascii)
                   (map score-test))
          test-keys (range 0 256)]
      (->> (merge-keys (into [] xf test-keys) test-keys)
           (remove #(nil? (:score %)))
           (sort-by :score)
           first))))

(defn single-byte-xor-cipher-hex
  "A hex encoded string has been XOR'd against a single character.
  Find the key, decrypt the message."
  [hex]
  (single-byte-xor-cipher (hex->bytes hex)))

;;- set 1: challenge 4 --------------------------------------------------------

(defn detect-single-character-xor
  "One of the 60-character strings in the file has been encrypted by
  single-character XOR. Find it."
  [file-path]
  (->> (string/split (slurp file-path) #"\n")
       (map single-byte-xor-cipher-hex)
       (sort-by :score)
       first))

;;- set 1: challenge 5 --------------------------------------------------------

(defn repeating-key-xor
  "Encrypt input, under the key, using repeating-key XOR."
  [input xor-key]
  (letfn [(repeat-xor [xor-key length]
            (let [xf (comp cat
                           (take length))
                  byte-key (map byte xor-key)]
              (into [] xf (repeat byte-key))))]
    (fixed-xor (map byte input)
               (repeat-xor xor-key (count input)))))

(defn repeating-key-xor-hex
  "Encrypt character input, under the key, using repeating-key XOR."
  [text xor-key]
  (bytes->hex (byte-array (repeating-key-xor text xor-key))))

;;- set 1: challenge 6 --------------------------------------------------------

(defn hamming-distance
  [x y]
  "The Hamming distance is just the number of differing bits."
  {:pre [(= (count x) (count y))]}
  (letfn [(bit-diff [[x y]]
            (Integer/bitCount (bit-xor x y)))]
    (reduce + (map bit-diff (zip x y)))))

(defn score-hamming [n file-bytes keysize]
  "Use n blocks of keysize to calculate average hamming distance between each."
  (let [blocks (take n (partition keysize file-bytes))
        scores (for [x blocks y blocks :while (not= x y)]
                 (/ (hamming-distance x y) keysize))]
    {:keysize keysize
     :score (/ (reduce + scores) (count scores))}))

(defn extract-xor-key
  "Create blocks of keysize, transpose and find best single bytekey.  Repeat for
  all blocks for the complete key."
  [file-bytes keysize]
  (let [get-key (comp byte->ascii
                      :key
                      single-byte-xor-cipher)
        transposed (apply zip (partition keysize file-bytes))]
    (apply str (map get-key transposed))))

(defn break-repeating-key-xor
  "Breaking repeating-key XOR (Vigenere) statistically is obviously an academic
  exercise, a 'Crypto 101' thing. But more people 'know how' to break it than
  can actually break it, and a similar technique breaks something much more
  important."
  [file-path {:keys [keysize-min
                     keysize-max
                     hamming-blocks
                     keysize-test-best]}]
  (let [file-bytes (base64file->bytes file-path)
        keysizes (range keysize-min keysize-max)
        get-score (partial score-hamming hamming-blocks file-bytes)
        get-key (partial extract-xor-key file-bytes)
        assoc-key #(assoc % :key (get-key (:keysize %)))
        is-english? #(is-english?-score (map char (repeating-key-xor file-bytes %)))
        assoc-english #(assoc % :is-english (is-english? (:key %)))]
    (->> (map get-score keysizes)
         (sort-by :score)
         (take keysize-test-best)
         (map assoc-key)
         (map assoc-english)
         (sort-by :is-english)
         first)))

;;- set 1: challenge 7 --------------------------------------------------------

(defn aes-ecb-mode-cipher
  "Use AES-128 in ECB mode to encrypt/decrypt the data."
  ([mode key data]
   (aes-ecb-mode-cipher "AES/ECB/NoPadding" mode key data))
  ([cipher mode key data]
   (let [secret (SecretKeySpec. (byte-array (map byte key)) "AES")
         ccipher (Cipher/getInstance cipher)
         cmode (case mode
                 :encrypt Cipher/ENCRYPT_MODE
                 :decrypt Cipher/DECRYPT_MODE)]
     (.init ccipher cmode secret)
     (.doFinal ccipher data))))

(defn aes-ecb-mode-decrypt-file
  "The Base64-encoded content in the file has been encrypted via AES-128 in ECB
  mode.  Decrypt it."
  [file-path key]
  (let [encrypted-data (base64file->bytes file-path)]
    (apply str (bytes->ascii (aes-ecb-mode-cipher :decrypt key encrypted-data)))))

;;- set 1: challenge 8 --------------------------------------------------------

(defn detect-aes-in-ecb-mode
  [block-size data]
  (let [split-blocks #(partition block-size %)
        has-duplicates #(not= (count %) (count (distinct %)))]
    (has-duplicates (split-blocks data))))

(defn detect-aes-in-ecb-mode-file
  [file-path]
  (let [encrypted-datas (string/split-lines (slurp file-path))]
    (filter (partial detect-aes-in-ecb-mode 16) encrypted-datas)))
