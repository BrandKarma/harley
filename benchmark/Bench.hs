module Main (main) where

import Criterion.Main (bgroup, defaultMain, whnf, bench)

fib :: Int -> Int
fib 0 = 0
fib 1 = 1
fib n = fib (n-1) + fib (n-2)


main :: IO ()
main = defaultMain
    [ bgroup "benchmarks" [bench "10" $ whnf fib 10]
    ]
