(ns cryptopals.core
  (:import
    (org.apache.commons.codec.binary Base64 Hex))
  (:gen-class))

(defn hex->bytes [hex]
  "Converts string hex to byte[]."
  (Hex/decodeHex (.toCharArray hex)))

(defn bytes->hex [bytes]
  "Converts byte[] to string hex."
  (apply str (Hex/encodeHex bytes)))

(defn hex->base64
  "Convert string of hex to base64."
  [hex]
  (Base64/encodeBase64String (hex->bytes hex)))

(defn fixed-xor
  "Takes two equal-length buffers and produces their XOR combination."
  [x y]
  {:pre [(= (count x) (count y))]}
  (let [bytes-x (hex->bytes x)
        bytes-y (hex->bytes y)
        zipped (map vector bytes-x bytes-y)]
    (bytes->hex (byte-array (map (partial apply bit-xor) zipped)))))

(defn -main
  ""
  [& args]
  (println "Nothing here."))
