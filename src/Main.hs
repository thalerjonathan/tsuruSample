module Main where

-- TODO: order imports
import Data.Maybe
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Char

fileName :: String
--fileName = "data/mdf-kospi200.20110216-0.pcap/data"
fileName = "test.txrt"

quotePacketMarker :: String
quotePacketMarker = "B6034"

main :: IO ()
main = do
  bs <- BL.readFile fileName
  
  let f = searchStream "print" bs
  if isJust f
    then (do
      putStrLn "found"
      let bs' = fromJust f
      printStream bs')
    else putStrLn "Not found"

  return ()

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
searchStream str bs = do
    (initWin, bs') <- initWindow (length str) [] bs
    (_, bs') <- nextQuoteAux str initWin bs'
    return bs'

  where
    nextQuoteAux :: String -> String -> BL.ByteString -> Maybe (String, BL.ByteString)
    nextQuoteAux str win bs = 
      if win == str
        then Just (win, bs)
        else do
          (win', bs') <- slideWindow win bs
          nextQuoteAux str win' bs'

    initWindow  :: Int -> String -> BL.ByteString -> Maybe (String, BL.ByteString)
    initWindow 0 str bs = Just (str, bs)
    initWindow n str bs = do
      (c, bs') <- BL.uncons bs
      initWindow (n - 1) (str ++ [c]) bs'

    slideWindow :: String -> BL.ByteString -> Maybe (String, BL.ByteString)
    slideWindow (_ : cs) bs = do
      (c, bs') <- BL.uncons bs
      pure (cs ++ [c], bs')