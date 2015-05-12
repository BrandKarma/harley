module HarleySpec (spec) where

import Test.Hspec

spec :: Spec
spec =
    describe "main" $ it "dummy equal" ((1 :: Int) == (1 :: Int))
   
