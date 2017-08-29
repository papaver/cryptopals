(ns cryptopals.core
  (:import
    (org.apache.commons.codec.binary Base64 Hex))
  (:gen-class))

(defn hex->base64
  "Convert hex to base64."
  [hex]
  (Base64/encodeBase64String (Hex/decodeHex (.toCharArray hex))))

(defn -main
  ""
  [& args]
  (println "Nothing here."))
