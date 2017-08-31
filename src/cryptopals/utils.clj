;;-----------------------------------------------------------------------------
;; The Matasano Crypto Challenges: Utility Functions
;;-----------------------------------------------------------------------------

(ns cryptopals.utils
  (:import
    [org.apache.commons.codec.binary Hex]))

;;- utils ---------------------------------------------------------------------

(defn hex->bytes
  "Converts hex string to byte[]."
  ([]
   (fn [rf]
     (fn
       ([] (rf))
       ([result] (rf result))
       ([result input] (reduce rf result (hex->bytes input))))))
  ([^String hex]
   (Hex/decodeHex (.toCharArray hex))))

(defn bytes->hex
  "Converts byte[] to hex string."
  [bs]
  (apply str (Hex/encodeHex bs)))

(defn byte->hex
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

(def bytes->ascii
  "Convert byte[] to ascii."
  (partial map byte->ascii))

(defn hex->ascii
  "Convert hex string to ascii string."
  [hex]
  (apply str (into []
                   (comp (hex->bytes)
                         (map byte->ascii))
                   [hex])))

(defn map-values [f m]
  (into {} (map (fn [[k v]] {k (f v)})) m))

(defn sqr-err
  "Calculate the sum of the error squared."
  [observed expected]
  (let [diff (- observed expected)]
    ((comp double /) (* diff diff) expected)))

(defn zip
  "Zip up one or more lists. Note the shortest list will dictate length."
  [& args]
  (apply map vector args))


