(ns cryptopals.core-test
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]))

;;- utils ---------------------------------------------------------------------

(deftest hex->bytes-test
  (testing "Convert hex to byte[]"
    (is (= [0] (map int (hex->bytes "00"))))
    (is (= [-1] (map int (hex->bytes "ff"))))))

(deftest bytes->hex-test
  (testing "Convert byte[] to hex"
    (is (= "00" (bytes->hex (byte-array [0]))))
    (is (= "ff" (bytes->hex (byte-array [-1]))))))

(deftest int->hex-test
  (testing "Convert int to hex"
    (is (= "00" (int->hex 0)))
    (is (= "ff" (int->hex 255)))))

(deftest byte->int-test
  (testing "Convert byte to int"
    (is (= 0 (byte->int (byte 0))))
    (is (= 255 (byte->int (byte -1))))))

(deftest hex->ascii-test
  (testing "Convert hex to ascii string"
    (is (= "ab" (hex->ascii "6162")))))

(deftest map-values-test
  (testing "Transforming values in a map"
    (is (= {:a 2 :b 3}
           (map-values inc {:a 1 :b 2})))))

(deftest a-z?-test
  (testing "Test for lowercase english characters"
    (is (a-z? \a))
    (is (not (a-z? \A)))
    (is (not (a-z? \?)))))

(deftest letter-frequencies-test
  (testing "English letter frequencies"
    (is (= {\b 3
            \c 4
            \d 6
            \e 12}
          (letter-frequencies "bbb CCCC!dddddd_eeeeeeeeeeee")))))

(deftest sqr-err-test
  (testing "Squared error test"
    (is (= 0.0 (sqr-err 5 5)))
    (is (= 0.2 (sqr-err 4 5)))
    (is (= 1.8 (sqr-err 2 5)))
    (is (= 3.2 (sqr-err 1 5)))))

;;- set 1 ---------------------------------------------------------------------

(deftest hex->base64-test
  (testing "Convert hex to base64"
    (is (= "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
           (hex->base64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))))

(deftest fixed-xor-test
  (testing "Fixed XOR"
    (is (= "746865206b696420646f6e277420706c6179"
           (fixed-xor "1c0111001f010100061a024b53535009181c"
                      "686974207468652062756c6c277320657965")))))

(deftest single-byte-xor-cipher-test
  (testing "Single-byte XOR cipher"
    (is (= "Cooking MC's like a pound of bacon"
           (:msg (single-byte-xor-cipher "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))))))

(deftest detect-single-character-xor-test
  (testing "Detect single-character XOR"
    (is (= "Now that the party is jumping\n"
           (:msg (detect-single-character-xor "resources/s1c4.txt"))))))
