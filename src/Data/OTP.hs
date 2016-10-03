{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Data.OTP (
    totp
) where

import Crypto.Hash.Algorithms (SHA1)
import Crypto.MAC.HMAC (HMAC, hmac)
import Data.Bits ((.&.))
import Data.ByteArray (unpack)
import Data.ByteString (ByteString, pack)
import Data.Serialize.Get (runGet, getWord32be)
import Data.Serialize.Put (runPut, putWord64be)
import Data.Time (UTCTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import Data.Word (Word, Word8, Word32, Word64)

newtype OTP = OTP (Word, Word32) deriving (Eq)
instance Show OTP where
    show (OTP (digits, otp)) =
        pad (show otp)
      where
        pad :: String -> String
        pad =
            let l = fromIntegral digits
                go xs = if length xs < l then go ('0':xs) else xs
             in go

-- inspired by https://github.com/s9gf4ult/one-time-password
hotp :: ByteString -> Word64 -> Word -> OTP
hotp key count digits =
    case (runGet getWord32be . pack . dt . unpack) hmacSHA1 of
        Left e  -> error e -- well, shit
        Right w -> OTP (digits, w `mod` 10 ^ digits)
  where
    hmacSHA1 :: HMAC SHA1
    hmacSHA1 = (hmac key . runPut . putWord64be) count

    dt :: [Word8] -> [Word8]
    dt ws =
        let offset = fromIntegral (last ws .&. 0xF) -- low 4 bits of last byte
            (p:ps) = take 4 (drop offset ws)        -- take 4 bytes from offset
         in (p .&. 0x7F) : ps                       -- zero first sig bit

totp :: ByteString -> UTCTime -> Word64 -> Word -> OTP
totp secret time period =
    let counter = floor (utcTimeToPOSIXSeconds time) `div` period
     in hotp secret counter
