;;-----------------------------------------------------------------------------
;; The Matasano Crypto Challenges: Test Suite
;;-----------------------------------------------------------------------------

(ns cryptopals.core-test
  (:require [clojure.test :refer :all]
            [cryptopals.utils :refer [bytes->str]]
            [cryptopals.core :refer :all]))

;;- set 2: challenge 1 --------------------------------------------------------

(deftest pkcs#7-padding-test
  (testing "Implement PKCS#7 padding"
    (is (= "YELLOW SUBMARINE\u0004\u0004\u0004\u0004"
           (bytes->str (pkcs#7-padding "YELLOW SUBMARINE" 20))))))
