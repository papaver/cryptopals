(ns cryptopals.core
  (:require [clojure.java.io :as io]
            [clojure.string :as string])
  (:import
    (org.apache.commons.codec.binary Base64 Hex))
  (:gen-class))

;;- utils ---------------------------------------------------------------------

(defn hex->bytes
  "Converts hex string to byte[]."
  ([]
   (fn [rf]
     (fn
       ([] (rf))
       ([result] (rf result))
       ([result input] (reduce rf result (hex->bytes input))))))
  ([hex]
   (Hex/decodeHex (.toCharArray hex))))

(defn bytes->hex
  "Converts byte[] to hex string."
  [bs]
  (apply str (Hex/encodeHex bs)))

(defn int->hex
  "Converts an integer into string hex."
  [i]
  (bytes->hex (byte-array [i])))

(defn byte->int
  "Converts a byte into an integer."
  [b]
  (bit-and 0xff b))

(def byte->ascii
  "Convert byte to ascii."
  (comp
    char
    byte->int))

(defn hex->ascii
  "Convert hex string to ascii string."
  [hex]
  (apply str (into [] (comp (hex->bytes)
                      (map byte->ascii)) [hex])))

(defn map-values [f m]
  (into {} (map (fn [[k v]] {k (f v)})) m))

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

(defn sqr-err
  "Calculate the sum of the error squared."
  [observed expected]
  (let [diff (- observed expected)]
    ((comp double /) (* diff diff) expected)))

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
  (let [bytes-x (hex->bytes x)
        bytes-y (hex->bytes y)
        zipped (map vector bytes-x bytes-y)]
    (bytes->hex (byte-array (map (partial apply bit-xor) zipped)))))

;;- set 1: challenge 3 --------------------------------------------------------

(def en-letter-frequencies
  "English language letter frequencies.
   reference: https://en.wikipedia.org/wiki/Letter_frequency"
  {\a 0.08167 \b 0.01492 \c 0.02782 \d 0.04253 \e 0.12702 \f 0.02228 \g 0.02015
   \h 0.06094 \i 0.06966 \j 0.00153 \k 0.00772 \l 0.04025 \m 0.02406 \n 0.06749
   \o 0.07507 \p 0.01929 \q 0.00095 \r 0.05987 \s 0.06327 \t 0.09056 \u 0.02758
   \v 0.00978 \w 0.02360 \x 0.00150 \y 0.01974 \z 0.00074})

(defn is-english?-score
  "Use chi-squared testing to score a string as english."
  [s]
  (try (let [s-freqs (letter-frequencies s)
             s-len (reduce + (vals s-freqs))
             en-freq-err (fn [k v] (sqr-err (get s-freqs k 0) (* s-len v)))]
         (reduce-kv #(+ %1 (en-freq-err %2 %3)) 0 en-letter-frequencies))
       (catch Exception e nil)))

(defn non-english-penelty
  "Penalize all characters not within the normal alphabet and punctuation."
  [s]
  (letfn [(bad-char [c]
            (not (re-matches #"[a-zA-Z?!,.' ]+" (str c))))]
    (reduce #(+ %1 (if (bad-char %2) 10.0 0.0)) 0 s)))

(defn single-byte-xor-cipher
  "A hex encoded string has been XOR'd against a single character.
  Find the key, decrypt the message."
  [hex]
  (let [hex-len (bit-shift-right (count hex) 1)]
    (letfn [(repeat-hex [xh]
              (apply str (take hex-len (repeat xh))))
            (score-test [s]
              (let [score (is-english?-score s)]
                {:msg s
                 :score (if (nil? score)
                            nil
                            (+ score (non-english-penelty s)))}))]
      (let [xf (comp (map int->hex)
                     (map repeat-hex)
                     (map (partial fixed-xor hex))
                     (map hex->ascii)
                     (map score-test)
                     (remove #(nil? (:score %))))]
        (->> (into [] xf (range 0 256))
             (sort-by #(:score %))
             first)))))

;;- set 1: challenge 4 --------------------------------------------------------

(defn detect-single-character-xor
  "One of the 60-character strings in the file has been encrypted by
  single-character XOR. Find it."
  [file-path]
  (->> (string/split (slurp file-path) #"\n")
       (map single-byte-xor-cipher)
       (sort-by #(:score %))
       first))

;;- set 1: challenge 5 --------------------------------------------------------

(defn repeating-key-xor
  "Encrypt input, under the key, using repeating-key XOR."
  [input xor-key]
  (letfn [(repeat-xor-hex [xor-key length]
            (let [xf (comp cat
                           (take length)
                           (map int)
                           (map int->hex))]
              (apply str (into [] xf (repeat xor-key)))))
          (ascii->hex [ascii]
            (apply str (map #(int->hex (int %)) ascii)))]
    (fixed-xor (ascii->hex input)
               (repeat-xor-hex xor-key (count input)))))

;;-----------------------------------------------------------------------------

(defn -main
  ""
  [& args]
  (println "Nothing here."))
