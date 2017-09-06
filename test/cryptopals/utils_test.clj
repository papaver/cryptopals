;;-----------------------------------------------------------------------------
;; The Matasano Crypto Challenges: Utility Functions: Test Suite
;;-----------------------------------------------------------------------------

(ns cryptopals.utils-test
  (:require [clojure.test :refer :all]
            [cryptopals.utils :refer :all]))

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

(deftest ->byte-test
  (testing "Convert number/char byte"
    (is (= 97 (->byte \a)))
    (is (= -1 (->byte -1)))
    (is (= -116 (->byte 140)))
    (is (= 0 (->byte 256)))))

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
