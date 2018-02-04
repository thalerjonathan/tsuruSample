module Main where

-- TODOS
--    ordering of imports
--    Hadoc comments for every function
--    structure into multiple files if necessary
--    implement in Idris (using Buffer for ByteString)

import Data.Char
import Data.Maybe
-- using LAZY otherwise would load the whole file into memory
-- profiling with stack:
--    stack build --profile
--    stack exec -- parse-quote +RTS -p
--    hp2ps -e8in -c parse-quote.hp#
--  LAZY:   memory footprint ~ 93 KByte
--  STRICT: memory footprint ~  6 MByte
import qualified Data.ByteString.Lazy.Char8 as BL

fileName :: String
fileName = "data/mdf-kospi200.20110216-0.pcap/data"

-- a Quote packet starts with this marker
quotePacketMarker :: String
quotePacketMarker = "B6034"

main :: IO ()
main = do
  -- TODO: replace with total function: check if file can be opened and not just throw error at run-time
  bs <- BL.readFile fileName
  let n = countQuotePackets bs
  putStrLn ("Found " ++ show n ++ " quote packets in stream")
  return ()

countQuotePackets :: BL.ByteString -> Int
countQuotePackets bs = countQuotePacketsAux bs 0
  where
    countQuotePacketsAux :: BL.ByteString -> Int -> Int
    countQuotePacketsAux bs acc
        | isJust res = countQuotePacketsAux (fromJust res) (acc + 1)
        | otherwise = acc
      where
        res = searchStream quotePacketMarker bs

printStream :: BL.ByteString -> IO ()
printStream bs = do
  let mayHead = BL.uncons bs
  if isNothing mayHead
    then return ()
    else do 
      let (c, bs') = fromJust mayHead
      putStr [c]
      printStream bs'

searchStream :: String -> BL.ByteString -> Maybe BL.ByteString
searchStream tok bs = do
    (initWin, bs') <- initWindow (length tok) [] bs
    (_, bs') <- searchStreamAux tok initWin bs'
    return bs'

  where
    searchStreamAux :: String -> String -> BL.ByteString -> Maybe (String, BL.ByteString)
    searchStreamAux tok win bs = 
      if win == tok
        then Just (win, bs)
        else do
          (win', bs') <- slideWindow win bs
          searchStreamAux tok win' bs'

    initWindow  :: Int -> String -> BL.ByteString -> Maybe (String, BL.ByteString)
    initWindow 0 str bs = Just (str, bs)
    initWindow n str bs = do
      (c, bs') <- BL.uncons bs
      initWindow (n - 1) (str ++ [c]) bs'

    slideWindow :: String -> BL.ByteString -> Maybe (String, BL.ByteString)
    slideWindow (_ : cs) bs = do
      (c, bs') <- BL.uncons bs
      pure (cs ++ [c], bs')