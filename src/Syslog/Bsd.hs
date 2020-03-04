{-# language NamedFieldPuns #-}

module Syslog.Bsd
  ( Message(..)
  , decode
  ) where

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
  , month :: !Chronos.Month
  , day :: !Chronos.DayOfMonth
  , hour :: !Word8
  , minute :: !Word8
  , second :: !Word8
  , host :: {-# UNPACK #-} !Bytes
  , process :: {-# UNPACK #-} !Bytes
  , processId :: {-# UNPACK #-} !Word32.Maybe
  , message :: {-# UNPACK #-} !Bytes
  }

decode :: Bytes -> Maybe Message
decode = Parser.parseBytesMaybe parser

parser :: Parser () s Message
parser = do
  Latin.char () '<'
  priority <- Latin.decWord32 ()
  Latin.char () '>'
  monthBytes <- Parser.take () 3
  month <- case resolveMonth monthBytes of
    Chronos.Month 12 -> Parser.fail ()
    m -> pure m
  -- There might be two spaces here since single-digit days get
  -- padded with a space.
  Latin.skipChar1 () ' '
  dayRaw <- Latin.decWord8 ()
  day <- if dayRaw < 32
    then pure (Chronos.DayOfMonth (fromIntegral dayRaw))
    else Parser.fail ()
  Latin.char () ' '
  hour <- Latin.decWord8 ()
  when (hour > 23) (Parser.fail ())
  Latin.char () ':'
  minute <- Latin.decWord8 ()
  when (minute > 59) (Parser.fail ())
  Latin.char () ':'
  second <- Latin.decWord8 ()
  when (second > 59) (Parser.fail ())
  Latin.char () ' '
  host <- Latin.takeTrailedBy () ' '
  -- TODO: This should actually be a takeWhile1.
  processStart <- Unsafe.cursor
  hasPid <- Parser.skipTrailedBy2 () 0x3A 0x5B
  processEndSucc <- Unsafe.cursor
  arr <- Unsafe.expose
  let process = Bytes arr processStart ((processEndSucc - 1) - processStart)
  case hasPid of
    False -> do
      Latin.skipChar ' '
      message <- Parser.remaining
      pure Message{priority,month,day,hour,minute,second,host,process,processId=Word32.nothing,message}
    True -> do
      pid <- Latin.decWord32 ()
      Latin.char2 () ']' ':'
      Latin.skipChar ' '
      message <- Parser.remaining
      pure Message{priority,month,day,hour,minute,second,host,process,processId=Word32.just pid,message}

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
