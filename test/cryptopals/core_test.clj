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
            (aes-cbc-mode-decrypt-file key iv "resources/s2c10.txt")
            "I'm back and I'm ringin' the bell \n")))))

(deftest aes-cbc-mode-encrypt-test
  (testing "Implement CBC mode: encrypt"
    (let [key "YELLOW SUBMARINE"
          iv (take (count key) (repeat 0))
          encrypted (base64file->bytes "resources/s2c10.txt")
          decrypted (bytes->ascii (aes-cbc-mode-decrypt key iv encrypted))]
      (aes-cbc-mode-encrypt key iv decrypted))))

;;- set 2: challenge 11 -------------------------------------------------------

(deftest aes-ecb-mode-encrypt-test
  (testing "ECB mode: encrypt"
    (let [key "YELLOW SUBMARINE"
          txt "ABCDEFGHIJKLMNOPQRSTUVWYXYZABCDE"
          txt-bytes (byte-array (map int txt))]
      (is (= (aes-ecb-mode-encrypt key txt)
             (map identity (cryptopals.set1/aes-ecb-mode-cipher :encrypt key txt-bytes)))))))

(deftest encryption-oracle-test
  (testing "An ECB/CBC detection oracle"
    (dotimes [_ 100]
      (is (let [input "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                [mode encrypted] (encryption-oracle input)
                is-ecb (cryptopals.set1/detect-aes-in-ecb-mode 16 encrypted)]
            (case mode
              :ecb is-ecb
              :cbc (not is-ecb)))))))

;;- set 2: challenge 12 -------------------------------------------------------

(deftest make-oracle-decryptor-test
  (testing "Byte-at-a-time ECB decryption (Simple)"
    (let [unknown (base64file->bytes "resources/s2c11.txt")
          oracle (make-oracle-decryptor unknown)]
      (testing "Discover the block size of the cipher"
        (is (= 16 (discover-block-size oracle))))
      (testing "Detect ECB mode"
        (let [input "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
          (is (cryptopals.set1/detect-aes-in-ecb-mode 16 (oracle input)))))
      (testing "Decryption of hidden text"
        (let [unknown-size (count unknown)
              decryptor (byte-at-a-time-ecb-decryption oracle 16)]
          (is (= (vec unknown)
                 (into [] decryptor (range unknown-size)))))))))

;;- set 2: challenge 13 -------------------------------------------------------

(deftest params->obj-test
  (testing "Write a k=v parsing routine, as if for a structured cookie"
    (is (= {:foo "bar"
            :baz "qux"
            :zap "zazzle"}
           (params->obj "foo=bar&baz=qux&zap=zazzle")))))

(deftest profile-for-test
  (testing "Write a function that encodes a user profile, given an email address"
    (is (= "email=foo@bar.com&uid=10&role=user"
           (profile-for "foo@bar.com")))
    (is (= "email=foo@bar.comroleadmin&uid=10&role=user"
           (profile-for "foo@bar.com&role=admin")))))

(deftest ecb-cut-and-paste-test
  (testing "ECB cut-and-paste"
    (is (re-find #"role=admin" (ecb-cut-and-paste)))))
