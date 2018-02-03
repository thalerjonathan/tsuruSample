module Main where

import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Char

fileName :: String
fileName = "data/mdf-kospi200.20110216-0.pcap/data"

main :: IO ()
main = do
  bs <- BL.readFile fileName
  let chunk = BL.take 2 bs
  BL.putStrLn chunk
  let x = BL.head chunk
  print (digitToInt x)