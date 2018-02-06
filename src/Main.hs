module Main where

-- TODOS
--    ordering of imports 
--    Hadoc comments for every function
--    structure into multiple files if necessary
--    implement in Idris (using Buffer for ByteString)

import Data.Maybe
import Data.Word
import Data.Time.Format
import Data.Time.Clock.POSIX

import Text.Printf

-- TODO: seems to consume more or less the whole file into memory
-- using LAZY otherwise would load the whole file into memory
-- profiling with stack:
--    stack build --profile
--    stack exec -- parse-quote +RTS -p
--    hp2ps -e8in -c parse-quote.hp
-- NOTE: we used the Data.Binary.Get package but it seemed that data was not read lazily
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Binary.Get

import Debug.Trace

-- represents an offering (ask or bid): (quantity, price)
newtype Offering = Offering (String, String)

-- TODO: how can we get the packet-time???
-- representing 5 best bids/asks as individual fields and not as list
-- faster access
data QuotePacket = QuotePacket 
  { qpPacketTime  :: !String 
  , qpIssueCode   :: !String
  , qpIssueSeqNo  :: !String
  , qpMktStatType :: !String

  , qpTotBidQtVol :: !String
  , qpBestBid_1   :: !Offering
  , qpBestBid_2   :: !Offering
  , qpBestBid_3   :: !Offering
  , qpBestBid_4   :: !Offering
  , qpBestBid_5   :: !Offering

  , qpTotAskQtVol :: !String
  , qpBestAsk_1   :: !Offering
  , qpBestAsk_2   :: !Offering
  , qpBestAsk_3   :: !Offering
  , qpBestAsk_4   :: !Offering
  , qpBestAsk_5   :: !Offering

  , qpAcceptTime  :: !String -- HHMMSSuu
  }

instance Show Offering where
  show (Offering (quantity, price)) = quantity ++ "@" ++ price

instance Show QuotePacket where
  show (QuotePacket 
    qpPacketTime
    qpIssueCode 
    _qpIssueSeqNo
    _qpMktStatType

    _qpTotBidQtVol
    qpBestBid_1
    qpBestBid_2
    qpBestBid_3
    qpBestBid_4
    qpBestBid_5

    _qpTotAskQtVol
    qpBestAsk_1
    qpBestAsk_2
    qpBestAsk_3
    qpBestAsk_4
    qpBestAsk_5

    qpAcceptTime) = qpPacketTime ++ " " ++
                    qpAcceptTime ++ " " ++ 
                    qpIssueCode ++ " " ++
                    show qpBestBid_5 ++ " " ++
                    show qpBestBid_4 ++ " " ++
                    show qpBestBid_3 ++ " " ++
                    show qpBestBid_2 ++ " " ++
                    show qpBestBid_1 ++ " " ++
                    show qpBestAsk_1 ++ " " ++
                    show qpBestAsk_2 ++ " " ++
                    show qpBestAsk_3 ++ " " ++
                    show qpBestAsk_4 ++ " " ++
                    show qpBestAsk_5

-- following https://wiki.wireshark.org/Development/LibpcapFileFormat#File_Format
data PcapGlobalHeader = PcapGlobalHeader
  { pcapMagicNumber  :: !Word32
  , pcapVersionMajor :: !Word16
  , pcapVersionMinor :: !Word16
  , pcapThisZone     :: !Word32
  , pcapSigFigs      :: !Word32
  , pcapSnapLen      :: !Word32
  , pcapNetwork      :: !Word32

  , pcapSwapped      :: !Bool
  } deriving Show

data PcapPacketHeader = PcapPacketHeader
  { pcapTsSec   :: !Word32
  , pcapTsUSec  :: !Word32
  , pcapIncLen  :: !Word32
  , pcapOrigLen :: !Word32
  } deriving Show


pcapMagicNumberIdent :: Word32
pcapMagicNumberIdent = 0xa1b2c3d4

pcapMagicNumberSwapped :: Word32
pcapMagicNumberSwapped = 0xd4c3b2a1

pcapMagicNumberNanoIdent :: Word32 
pcapMagicNumberNanoIdent = 0xa1b23c4d

pcapMagicNumberNanoSwapped :: Word32 
pcapMagicNumberNanoSwapped = 0x4d3cb2a1

kosPcapFileName :: String
kosPcapFileName = "data/mdf-kospi200.20110216-0.pcap/data"

kosPcapSuperSizeFileName :: String
kosPcapSuperSizeFileName = "data/mdf-kospi200.20110216-0.pcap/dataBig"

-- a Quote packet starts with this marker
quotePacketMarker :: String
quotePacketMarker = "B6034"

main :: IO ()
main = do
  let fileName = kosPcapFileName -- kosPcapSuperSizeFileName -- kosPcapFileName -- "src/Main.hs"

  -- TODO: replace with total function: check if file can be opened and not just throw error at run-time
  bs <- BL.readFile fileName

  let mayGlobalHeader = readPcapGlobalHeader bs 
  if isNothing mayGlobalHeader
    then putStrLn ("Error: '" ++ fileName ++ "' not a PCAP file - exit")
    else do
      let (gh, bs') = fromJust mayGlobalHeader
      let headerSwapped = pcapSwapped gh
      putStrLn ("Valid pcap file, header: " ++ show gh)
      -- TODO: use getOpts to check for -r 
      printQuotePacketsArrival headerSwapped bs'

rushThrough :: BL.ByteString -> Maybe BL.ByteString
rushThrough bs = do
  (bs', c) <- BL.unsnoc bs
  rushThrough bs'

printQuotePacketsArrival :: Bool -> BL.ByteString -> IO ()
printQuotePacketsArrival headerSwapped bs = do
  let mayPh = nextQuotePacket headerSwapped bs
  if isJust mayPh
    then do
      let (qp, bs') = fromJust mayPh
      print qp
      printQuotePacketsArrival headerSwapped bs'
    else putStrLn "Failed reading next packet, proably EOS"

-- TODO: when re-ordering, then can expect packages to arrive out-of-order up to 3 seconds
printQuotePacketsInOrder :: Bool -> BL.ByteString -> IO ()
printQuotePacketsInOrder headerSwapped bs = do
  let mayPh = nextQuotePacket headerSwapped bs
  if isJust mayPh
    then do
      let (qp, bs') = fromJust mayPh
      print qp
      printQuotePacketsInOrder headerSwapped bs'
    else putStrLn "Failed reading next packet, proably EOS"

nextQuotePacket :: Bool -> BL.ByteString -> Maybe (QuotePacket, BL.ByteString)
nextQuotePacket headerSwapped bs = either 
    -- TODO: remove trace
    (\(_, _, errMsg) -> trace errMsg Nothing) 
    (\(bs', _off, mayqp) -> 
      if isJust mayqp
        then Just (fromJust mayqp, bs')
        else nextQuotePacket headerSwapped bs')
    (runGetOrFail searchQuotePacket bs)
  where
    searchQuotePacket :: Get (Maybe QuotePacket)
    searchQuotePacket = do
      ph <- readNextPacketHeader headerSwapped

      -- skipping 42 bytes of various frames/ethernII/IPv4/UDP
      skip 42 

      -- packet-data starts, check if it starts with B6034, then its a quote-packet
      qpHdr <- getLazyByteString 5
      if BL.unpack qpHdr /= quotePacketMarker
        then do
          let packetLen = pcapIncLen ph
          -- skip to the end of the packet, need to subtract the already consumed 42 and 5 bytes
          let skipBytes = fromIntegral packetLen - 5 - 42
          skip skipBytes
          return Nothing
        else do
          let secs       = pcapTsSec ph
          -- usecs are stored in values up to 100,000, we just need the first 2 digits => divide by 10,000
              usecs      = (fromIntegral $ pcapTsUSec ph) :: Double
              usecsFract = (truncate $ usecs / 10000) :: Int

          let utcTime = posixSecondsToUTCTime (fromIntegral secs)
              ts      = formatTime defaultTimeLocale "%H%M%S" utcTime -- format to same as quote accept time: HHMMSSuu
              ts'     = ts ++ printf "%02d" usecsFract

          qp <- parseQuotePacket ts'
          return $ Just qp

{-
nextQuotePacket :: Bool -> BL.ByteString -> Maybe (QuotePacket, BL.ByteString)
nextQuotePacket headerSwapped bs = either 
    (\(_, _, errMsg) -> trace errMsg Nothing) 
    (\(bs', off, qp) -> trace ("offset = " ++ show off) (Just (qp, bs')))
    (runGetOrFail searchQuotePacket bs)
  where
    searchQuotePacket :: Get QuotePacket 
    searchQuotePacket = do
      ph <- readNextPacketHeader headerSwapped

      -- skipping 42 bytes of various frames/ethernII/IPv4/UDP
      skip 42 

      -- packet-data starts, check if it starts with B6034, then its a quote-packet
      qpHdr <- getLazyByteString 5
      if BL.unpack qpHdr /= quotePacketMarker
        then do
          let packetLen = pcapIncLen ph
          -- skip to the end of the packet, need to subtract the already consumed 42 and 5 bytes
          let skipBytes = fromIntegral packetLen - 5 - 42
          skip skipBytes
          searchQuotePacket
        else do
          let secs = pcapTsSec ph
          let utcTime = posixSecondsToUTCTime (fromIntegral secs)
          let ts = formatTime defaultTimeLocale "%T" utcTime -- format to same as quote accept time: HHMMSSuu
          parseQuotePacket ts
  -}

parseQuotePacket :: String -> Get QuotePacket
parseQuotePacket ts = do
    issueCode <- getLazyByteString 12
    issueSeqNo <- getLazyByteString 3
    mktStatType <- getLazyByteString 2
    
    totBidQtVol <- getLazyByteString 7
    bestBid_1 <- parseOffering
    bestBid_2 <- parseOffering
    bestBid_3 <- parseOffering
    bestBid_4 <- parseOffering
    bestBid_5 <- parseOffering

    totAskQtVol <- getLazyByteString 7
    bestAsk_1 <- parseOffering
    bestAsk_2 <- parseOffering
    bestAsk_3 <- parseOffering
    bestAsk_4 <- parseOffering
    bestAsk_5 <- parseOffering

    -- skipping ahead to quote accept time: 2x 25 bytes (2x(5 + 4*5)) = 50
    {-  
    No. of best bid valid quote(total)      5
    No. of best bid quote(1st)              4
    No. of best bid quote(2nd)              4
    No. of best bid quote(3rd)              4
    No. of best bid quote(4th)              4
    No. of best bid quote(5th)              4
    No. of best ask valid quote(total)      5
    No. of best ask quote(1st)              4
    No. of best ask quote(2nd)              4
    No. of best ask quote(3rd)              4
    No. of best ask quote(4th)              4
    No. of best ask quote(5th)              4
    -}
    skip 50

    acceptTime <- getLazyByteString 8

    -- skipping end of message: 1 byte
    -- endOfMessage <- getWord8
    skip 1

    return $! QuotePacket {
      qpPacketTime  = ts
    , qpIssueCode   = BL.unpack issueCode
    , qpIssueSeqNo  = BL.unpack issueSeqNo
    , qpMktStatType = BL.unpack mktStatType

    , qpTotBidQtVol = BL.unpack totBidQtVol
    , qpBestBid_1   = bestBid_1
    , qpBestBid_2   = bestBid_2
    , qpBestBid_3   = bestBid_3
    , qpBestBid_4   = bestBid_4
    , qpBestBid_5   = bestBid_5

    , qpTotAskQtVol = BL.unpack totAskQtVol
    , qpBestAsk_1    = bestAsk_1
    , qpBestAsk_2    = bestAsk_2
    , qpBestAsk_3    = bestAsk_3
    , qpBestAsk_4    = bestAsk_4
    , qpBestAsk_5    = bestAsk_5

    , qpAcceptTime  = BL.unpack acceptTime
    }
  where
    parseOffering :: Get Offering
    parseOffering = do
      price <- getLazyByteString 5
      quantity <- getLazyByteString 7
      return $ Offering (BL.unpack price, BL.unpack quantity)

readPcapGlobalHeader :: BL.ByteString -> Maybe (PcapGlobalHeader, BL.ByteString)
readPcapGlobalHeader bs = do
    let ret = runGetOrFail readPcapGlobalHeaderAux bs
    either 
      (const Nothing) 
      (\(bs', _off, mayPcapHeader) -> 
        if isJust mayPcapHeader
          then Just (fromJust mayPcapHeader, bs')
          else Nothing)
      ret
  where
    readPcapGlobalHeaderAux :: Get (Maybe PcapGlobalHeader)
    readPcapGlobalHeaderAux = do
      magicNumber <- getWord32be

      if magicNumber == pcapMagicNumberIdent || 
         magicNumber == pcapMagicNumberNanoIdent
        then do
          gh <- readPcapGlobalHeaderIdent
          return $ Just gh
        else if magicNumber == pcapMagicNumberSwapped ||
                magicNumber == pcapMagicNumberNanoSwapped
          then do
            gh <- readPcapGlobalHeaderSwapped
            return $ Just gh
          else return Nothing

    readPcapGlobalHeaderIdent :: Get PcapGlobalHeader
    readPcapGlobalHeaderIdent = do
      versionMajor <- getWord16be
      versionMinor <- getWord16be
      thisZone <- getWord32be
      accuracyTs <- getWord32be
      snaplen <- getWord32be
      network <- getWord32be

      return PcapGlobalHeader {
        pcapMagicNumber  = 0xa1b2c3d4
      , pcapVersionMajor = versionMajor
      , pcapVersionMinor = versionMinor
      , pcapThisZone     = thisZone
      , pcapSigFigs      = accuracyTs
      , pcapSnapLen      = snaplen
      , pcapNetwork      = network
      , pcapSwapped      = False
      }

    readPcapGlobalHeaderSwapped :: Get PcapGlobalHeader
    readPcapGlobalHeaderSwapped = do
      versionMajor <- getWord16le
      versionMinor <- getWord16le
      thisZone <- getWord32le
      accuracyTs <- getWord32le
      snaplen <- getWord32le
      network <- getWord32le

      return PcapGlobalHeader {
        pcapMagicNumber  = 0xd4c3b2a1
      , pcapVersionMajor = versionMajor
      , pcapVersionMinor = versionMinor
      , pcapThisZone     = thisZone
      , pcapSigFigs      = accuracyTs
      , pcapSnapLen      = snaplen
      , pcapNetwork      = network
      , pcapSwapped      = True
      }

readNextPacketHeader :: Bool -> Get PcapPacketHeader
readNextPacketHeader True = do
  tsSec <- getWord32le
  tsUsec <- getWord32le
  inclLen <- getWord32le
  origLen <- getWord32le

  return PcapPacketHeader {
    pcapTsSec   = tsSec
  , pcapTsUSec  = tsUsec
  , pcapIncLen  = inclLen
  , pcapOrigLen = origLen
  }
readNextPacketHeader False = do
  tsSec <- getWord32be
  tsUsec <- getWord32be
  inclLen <- getWord32be
  origLen <- getWord32be

  return PcapPacketHeader {
    pcapTsSec   = tsSec
  , pcapTsUSec  = tsUsec
  , pcapIncLen  = inclLen
  , pcapOrigLen = origLen
  }