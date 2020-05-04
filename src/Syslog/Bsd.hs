{-# language NamedFieldPuns #-}

-- | Parse RFC 3164 messages. For example:
--
-- > <133>Feb 25 14:09:07 webserver syslogd: restart
-- > <0>Oct 22 10:52:01 scapegoat.dmz.example.org sched[0]: That's All Folks!
--
-- This library assumes that the @TAG@ field described by section 5.3 of
-- RFC 3164 is a process name. It also assumes that the optional bracketed
-- number that follows it is a process id.
module Syslog.Bsd
  ( -- * Types
    Message(..)
  , Process(..)
  , Timestamp(..)
    -- * Full Decode
  , decode
  , parser
    -- * Parsing Fragments
  , takePriority
  , takeTimestamp
  , takeHostname
  , takeProcess
  ) where

import Prelude hiding (id)

import Control.Monad (when)
import Data.Bytes.Types (Bytes(Bytes))
import Data.Bytes.Parser (Parser)
import Data.Word (Word8,Word32)

import qualified Chronos
import qualified Data.Bytes as Bytes
import qualified Data.Maybe.Unpacked.Numeric.Word32 as Word32
import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe

data Message = Message
  { priority :: !Word32
  , timestamp :: !Timestamp
  , hostname :: {-# UNPACK #-} !Bytes
  , process :: {-# UNPACK #-} !Process
  , message :: {-# UNPACK #-} !Bytes
  }

data Timestamp = Timestamp
  { month :: !Chronos.Month
  , day :: !Chronos.DayOfMonth
  , hour :: !Word8
  , minute :: !Word8
  , second :: !Word8
  , year :: {-# UNPACK #-} !Word32.Maybe
    -- ^ Section 5.1 of RFC 3164 notes that some software appends
    -- a four-character year after the time of day. Since hostnames
    -- cannot start with digits, we can parse this unambiguously. We
    -- extend RFC 3164 to handle these nonstandard years.
  }

data Process = Process
  { name :: {-# UNPACK #-} !Bytes
  , id :: {-# UNPACK #-} !Word32.Maybe
  }

-- | Run the RFC 3164 parser. See 'parser'.
decode :: Bytes -> Maybe Message
decode = Parser.parseBytesMaybe parser

-- | Parse a RFC 3164 message. Note that this is just @takePriority@,
-- @takeTimestamp@, @takeHostname, and @takeProcess@ called in sequence,
-- followed by skipping whitespace and then treating the remaining input
-- as the original message.
parser :: Parser () s Message
parser = do
  priority <- takePriority ()
  timestamp <- takeTimestamp ()
  hostname <- takeHostname ()
  process <- takeProcess ()
  Latin.skipChar ' '
  message <- Parser.remaining
  pure Message{priority,timestamp,hostname,process,message}

-- | Consume the angle-bracketed priority. RFC 3164 does not allow
-- a space to follow the priority, so this does not consume a
-- trailing space.
takePriority :: e -> Parser e s Word32
takePriority e = do
  Latin.char e '<'
  priority <- Latin.decWord32 e
  Latin.char e '>'
  pure priority

-- | Consume the hostname and the space that follows it. Returns
-- the hostname.
takeHostname :: e -> Parser e s Bytes
takeHostname e =
  -- TODO: This should actually use a takeWhile1.
  Latin.takeTrailedBy e ' '

-- | Consume the timestamp and the space that follows it. Returns
-- the parsed timestamp.
takeTimestamp :: e -> Parser e s Timestamp
takeTimestamp e = do
  monthBytes <- Parser.take e 3
  month <- case resolveMonth monthBytes of
    Chronos.Month 12 -> Parser.fail e
    m -> pure m
  -- There might be two spaces here since single-digit days get
  -- padded with a space.
  Latin.skipChar1 e ' '
  dayRaw <- Latin.decWord8 e
  day <- if dayRaw < 32
    then pure (Chronos.DayOfMonth (fromIntegral dayRaw))
    else Parser.fail e
  Latin.char e ' '
  hour <- Latin.decWord8 e
  when (hour > 23) (Parser.fail e)
  Latin.char e ':'
  minute <- Latin.decWord8 e
  when (minute > 59) (Parser.fail e)
  Latin.char e ':'
  second <- Latin.decWord8 e
  when (second > 59) (Parser.fail e)
  Latin.char e ' '
  -- The only good way to allow a year is with backtracking. We do not
  -- learn until we encounter the space following the decimal number
  -- whether it was a year or part of a hostname (likely an ip address).
  Parser.orElse
    ( do y <- Latin.decWord32 e
         Latin.char e ' '
         pure Timestamp{month,day,hour,minute,second,year=Word32.just y}
    )
    (pure Timestamp{month,day,hour,minute,second,year=Word32.nothing})

-- | Take the process name and the process id and consume the colon
-- that follows them. Does not consume any space after the colon.
takeProcess :: e -> Parser e s Process
takeProcess e = do
  processStart <- Unsafe.cursor
  hasPid <- Parser.skipTrailedBy2 e 0x3A 0x5B
  processEndSucc <- Unsafe.cursor
  arr <- Unsafe.expose
  let name = Bytes arr processStart ((processEndSucc - 1) - processStart)
  case hasPid of
    False -> pure Process{name,id=Word32.nothing}
    True -> do
      pid <- Latin.decWord32 e
      Latin.char2 e ']' ':'
      pure Process{name,id=Word32.just pid}

-- Precondition: length of bytes is 3
resolveMonth :: Bytes -> Chronos.Month
resolveMonth b
  | Bytes.equalsLatin3 'A' 'p' 'r' b = Chronos.april
  | Bytes.equalsLatin3 'A' 'u' 'g' b = Chronos.august
  | Bytes.equalsLatin3 'D' 'e' 'c' b = Chronos.december
  | Bytes.equalsLatin3 'F' 'e' 'b' b = Chronos.february
  | Bytes.equalsLatin3 'J' 'a' 'n' b = Chronos.january
  | Bytes.equalsLatin3 'J' 'u' 'l' b = Chronos.july
  | Bytes.equalsLatin3 'J' 'u' 'n' b = Chronos.june
  | Bytes.equalsLatin3 'M' 'a' 'r' b = Chronos.march
  | Bytes.equalsLatin3 'M' 'a' 'y' b = Chronos.may
  | Bytes.equalsLatin3 'N' 'o' 'v' b = Chronos.november
  | Bytes.equalsLatin3 'O' 'c' 't' b = Chronos.october
  | Bytes.equalsLatin3 'S' 'e' 'p' b = Chronos.september
  | otherwise = Chronos.Month 12
