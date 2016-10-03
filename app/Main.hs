import Codec.Binary.Base32 (decode)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B8
import Data.Char (toUpper)
import Data.Time.Clock.POSIX (getCurrentTime)
import Data.Version (showVersion)
import Options.Applicative
import Paths_otp (version)

import Data.OTP (totp)

data Options = Version | Base32Key ByteString

opts :: ParserInfo Options
opts =
    let synopsis = "otp - Generate RFC 6238 time-based one-time passwords"
        parser = flag' Version (long "version" <> hidden) <|>
                       (Base32Key <$> (helper <*> base32key))
     in info parser (header synopsis)
  where
    base32key :: Parser ByteString
    base32key = B8.pack . mconcat <$>
        some (argument str (metavar "KEY" <> help "Base 32 encoded key"))

main :: IO ()
main = do
    opt <- execParser opts
    case opt of
        Version       -> putStrLn (showVersion version)
        Base32Key key ->
            case decode (B8.map toUpper key) of
                Left _  -> error "Unable to decode base 32 key"
                Right k -> do
                    time <- getCurrentTime
                    print (totp k time 30 6)
