;;-----------------------------------------------------------------------------
;; The Matasano Crypto Challenges: Test Suite
;;-----------------------------------------------------------------------------

(ns cryptopals.core-test
  (:require [clojure.string :as string]
            [clojure.test :refer :all]
            [cryptopals.utils :refer [bytes->str
                                      bytes->ascii
                                      base64file->bytes]]
            [cryptopals.core :refer :all]))

;;- set 2: challenge 9 --------------------------------------------------------

(deftest pkcs#7-padding-test
  (testing "Implement PKCS#7 padding"
    (is (= "YELLOW SUBMARINE\u0004\u0004\u0004\u0004"
           (bytes->str (pkcs#7-padding 20 "YELLOW SUBMARINE"))))))

;;- set 2: challenge 10 -------------------------------------------------------

(deftest aes-cbc-mode-decrypt-file-test
  (testing "Implement CBC mode: decrypt"
    (let [key "YELLOW SUBMARINE"
          iv (take (count key) (repeat 0))]
      (is (string/starts-with?
            (aes-cbc-mode-decrypt-file "resources/s2c10.txt" key iv)
            "I'm back and I'm ringin' the bell \n")))))

(deftest aes-cbc-mode-encrypt-test
  (testing "Implement CBC mode: encrypt"
    (let [key "YELLOW SUBMARINE"
          iv (take (count key) (repeat 0))
          encrypted (base64file->bytes "resources/s2c10.txt")
          decrypted (bytes->ascii (aes-cbc-mode-decrypt encrypted key iv))]
      (aes-cbc-mode-encrypt decrypted key iv))))
