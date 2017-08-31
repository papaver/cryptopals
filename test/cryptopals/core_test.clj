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

(deftest byte->hex-test
  (testing "Convert int to hex"
    (is (= "00" (byte->hex 0)))
    (is (= "ff" (byte->hex 255)))))

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

(deftest sqr-err-test
  (testing "Squared error test"
    (is (= 0.0 (sqr-err 5 5)))
    (is (= 0.2 (sqr-err 4 5)))
    (is (= 1.8 (sqr-err 2 5)))
    (is (= 3.2 (sqr-err 1 5)))))

(deftest zip-test
  (testing "Zipping together sequences"
    (is (= [[:a] [:b] [:c]] (zip [:a :b :c])))
    (is (= [[:a :d] [:b :e] [:c :f]] (zip [:a :b :c] [:d :e :f])))
    (is (= [[:a :d :g] [:b :e :h] [:c :f :i]] (zip [:a :b :c] [:d :e :f] [:g :h :i])))
    (is (= [[:a :d :g] [:b :e :h]] (zip [:a :b :c] [:d :e :f] [:g :h])))))

;;- set 1: challenge 1 --------------------------------------------------------

(deftest hex->base64-test
  (testing "Convert hex to base64"
    (is (= "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
           (hex->base64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))))

;;- set 1: challenge 2 --------------------------------------------------------

(deftest fixed-xor-hex-test
  (testing "Fixed XOR"
    (is (= "746865206b696420646f6e277420706c6179"
           (fixed-xor-hex "1c0111001f010100061a024b53535009181c"
                          "686974207468652062756c6c277320657965")))))

;;- set 1: challenge 3 --------------------------------------------------------

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

(deftest non-english-penelty-test
  (testing "Non-English characters penelty"
    (is (= 0.0 (non-english-penelty "abcdefg")))
    (is (= 50.0 (non-english-penelty "._|[]{")))))

(deftest single-byte-xor-cipher-hex-test
  (testing "Single-byte XOR cipher"
    (is (= "Cooking MC's like a pound of bacon"
           (:msg (single-byte-xor-cipher-hex "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))))))

;;- set 1: challenge 4 --------------------------------------------------------

(deftest detect-single-character-xor-test
  (testing "Detect single-character XOR"
    (is (= "Now that the party is jumping\n"
           (:msg (detect-single-character-xor "resources/s1c4.txt"))))))

;;- set 1: challenge 5 --------------------------------------------------------

(deftest repeating-key-xor-hex-test
  (testing "Implement repeating-key XOR"
    (is (= (str "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
           (repeating-key-xor-hex (str "Burning 'em, if you ain't quick and nimble\n"
                                       "I go crazy when I hear a cymbal")
                                  "ICE")))))

;;- set 1: challenge 6 --------------------------------------------------------

(deftest hamming-distance-test
  (testing "Hamming distance"
    (is (= 37 (hamming-distance (map byte "this is a test")
                                (map byte "wokka wokka!!!"))))))

(deftest break-repeating-key-xor-test
  (testing "Break repeating-key XOR"
    (is (= "Terminator X: Bring the noise"
           (:key (break-repeating-key-xor "resources/s1c6.txt"
                                          {:keysize-min 2
                                           :keysize-max 40
                                           :hamming-blocks 5
                                           :keysize-test-best 3}))))))
