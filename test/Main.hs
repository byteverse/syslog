{-# language DuplicateRecordFields #-}
{-# language NamedFieldPuns #-}

import Prelude hiding (id)

import Data.Bytes (Bytes)
import Data.Maybe (isNothing)
import Syslog.Bsd (Message(Message),Process(Process))

import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Text.Latin1 as Latin1
import qualified Data.Primitive as PM
import qualified Syslog.Bsd as Bsd
import qualified Syslog.Ietf as Ietf

main :: IO ()
main = do
  putStrLn "Starting"
  putStrLn "Test A"
  case Bsd.decode msgA of
    Nothing -> fail "Could not decode message A"
    Just Message{priority,hostname,process=Just Process{name},message} -> do
      assert "priority" (priority == 133)
      assert "hostname" (hostname == Latin1.fromString "webserver")
      assert "process_name" (name == Latin1.fromString "syslogd")
      assert "message" (message == Latin1.fromString "restart")
    Just _ -> fail "Message A missing process name"
  putStrLn "Test B"
  case Bsd.decode msgB of
    Nothing -> fail "Could not decode message B"
    Just Message{priority,hostname,process=Just Process{name},message} -> do
      assert "priority" (priority == 0)
      assert "hostname" (hostname == Latin1.fromString "foo.example.org")
      assert "process_name" (name == Latin1.fromString "sched")
      assert "message" (message == Latin1.fromString "That's all")
    Just _ -> fail "Message B missing process name"
  putStrLn "Test C"
  case Bsd.decode msgC of
    Nothing -> fail "Could not decode message C"
    Just Message{priority,hostname,process=Just Process{name},message} -> do
      assert "priority" (priority == 133)
      assert "hostname" (hostname == Latin1.fromString "192.0.2.231")
      assert "process_name" (name == Latin1.fromString "stm")
      assert "message" (message == Latin1.fromString "Hello")
    Just _ -> fail "Message C missing process name"
  putStrLn "Test D"
  case Bsd.decode msgD of
    Nothing -> fail "Could not decode message D"
    Just Message{priority,process,message} -> do
      assert "priority" (priority == 26)
      assert "process_name" (isNothing process)
      assert "message" (message == Latin1.fromString "ASA log")
  putStrLn "Test E"
  case Bsd.decode msgE of
    Nothing -> fail "Could not decode message E"
    Just Message{process} -> case process of
      Just Process{priority,name} -> do
        assert "process_priority" (priority == Latin1.fromString "notice")
        assert "process_name" (name == Latin1.fromString "tmsh")
      Nothing -> fail "Message E missing process information"
  putStrLn "Test F"
  case Bsd.decode msgF of
    Nothing -> fail "Could not decode message F"
    Just Message{message} -> do
      assert "message" (message == Latin1.fromString "foo")
  putStrLn "Test G"
  case Bsd.decode msgG of
    Nothing -> fail "Could not decode message G"
    Just{} -> pure ()
  putStrLn "Test IETF A"
  case Ietf.decode ietfA of
    Nothing -> fail "Could not decode IETF message A"
    Just Ietf.Message{version,hostname,structuredData} -> do
      assert "version" (version == 1)
      assert "hostname" (hostname == Latin1.fromString "mymachine.example.com")
      assert "structured_data_length" (length structuredData == 1)
  putStrLn "Test IETF B"
  case Ietf.decode ietfB of
    Nothing -> fail "Could not decode IETF message B"
    Just Ietf.Message{version,hostname,application,messageType,structuredData} -> do
      assert "version" (version == 1)
      assert "hostname" (hostname == Latin1.fromString "FOOBAR-SRX-FWL0")
      assert "application" (application == Latin1.fromString "RT_FLOW")
      assert "message_type" (messageType == Latin1.fromString "RT_FLOW_SESSION_CLOSE")
      assert "structured_data_length" (length structuredData == 1)
      let Ietf.Element{id,parameters} = PM.indexSmallArray structuredData 0
      assert "structured_data.id" (id == Latin1.fromString "junos@2636.1.1.1.2.133")
      assert "structured_data.parameters_length" (length parameters == 32)
  putStrLn "Test IETF C"
  case Ietf.decode ietfC of
    Nothing -> fail "Could not decode IETF message C"
    Just Ietf.Message{version,hostname,application,messageType,structuredData,message} -> do
      assert "version" (version == 1)
      assert "hostname" (hostname == Latin1.fromString "mymachine.example.com")
      assert "application" (application == Latin1.fromString "bigapp")
      assert "message_type" (Bytes.null messageType)
      assert "structured_data_length" (length structuredData == 0)
      assert "message" (message == Latin1.fromString "hey world")
  putStrLn "Test IETF D"
  case Ietf.decode ietfD of
    Nothing -> fail "Could not decode IETF message D"
    Just Ietf.Message{message,structuredData} -> do
      assert "structured_data_length" (length structuredData == 3)
      let Ietf.Element{parameters} = PM.indexSmallArray structuredData 2
      assert "parameters_length" (length parameters == 1)
      let Ietf.Parameter{value} = PM.indexSmallArray parameters 0
      case value == Latin1.fromString "\\foo\\bar.txt" of
        True -> pure ()
        False -> fail ("structured_data.2.0: " ++ show value)
      assert "message" (message == Latin1.fromString "bad news")
  putStrLn "Test IETF E"
  case Ietf.decode ietfE of
    Nothing -> fail "Could not decode IETF message E"
    Just _ -> pure ()
  putStrLn "Test IETF F"
  case Ietf.decode ietfF of
    Nothing -> fail "Could not decode IETF message F"
    Just _ -> pure ()
  putStrLn "Finished"

assert :: String -> Bool -> IO ()
assert ctx b = if b then pure () else fail ctx

msgA, msgB, msgC, msgD, msgE, msgF, msgG :: Bytes
msgA = Latin1.fromString "<133>Feb 25 14:09:07 webserver syslogd: restart"
msgB = Latin1.fromString "<0>Oct 22 10:52:01 foo.example.org sched[0]: That's all"
msgC = Latin1.fromString "<133>May  2 11:43:37 2020 192.0.2.231 stm[8753]:  Hello"
msgD = Latin1.fromString "<26>May 05 2020 07:30:21 192.0.2.10 : ASA log"
msgE = Latin1.fromString "<133>Aug 10 07:12:13 example.local notice tmsh[4067]: hey"
msgF = Latin1.fromString "<133>Aug 10 07:12:13: foo"
msgG = Latin1.fromString "<134>Oct 30 12:31:49 10.22.16.11 logrhythm: <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"

ietfA :: Bytes
ietfA = Latin1.fromString $ concat
  [ "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
  , "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] "
  , "BOMAn application event log entry"
  ]

ietfB :: Bytes
ietfB = Latin1.fromString $ concat
  [ "<14>1 2020-10-15T17:01:23.466Z FOOBAR-SRX-FWL0 RT_FLOW - RT_FLOW_SESSION_CLOSE "
  , "[junos@2636.1.1.1.2.133 reason=\"application failure or action\" "
  , "source-address=\"192.0.2.29\" source-port=\"55110\" "
  , "destination-address=\"192.0.2.30\" destination-port=\"135\" connection-tag=\"0\" "
  , "service-name=\"junos-ms-rpc-tcp\" nat-source-address=\"192.0.2.229\" "
  , "nat-source-port=\"55110\" nat-destination-address=\"192.0.2.230\" "
  , "nat-destination-port=\"135\" nat-connection-tag=\"0\" src-nat-rule-type=\"N/A\" "
  , "src-nat-rule-name=\"N/A\" dst-nat-rule-type=\"N/A\" dst-nat-rule-name=\"N/A\" "
  , "protocol-id=\"6\" policy-name=\"EXAMPLE-POLICY\" "
  , "source-zone-name=\"MYSRCZONE\" destination-zone-name=\"MYDSTZONE\" "
  , "session-id-32=\"14953\" packets-from-client=\"0\" bytes-from-client=\"0\" "
  , "packets-from-server=\"0\" bytes-from-server=\"0\" elapsed-time=\"1\" "
  , "application=\"UNKNOWN\" nested-application=\"UNKNOWN\" username=\"N/A\" "
  , "roles=\"N/A\" packet-incoming-interface=\"ge-0/0/5.0\" encrypted=\"UNKNOWN\"] "
  , "session closed application failure or action"
  ]

ietfC :: Bytes
ietfC = Latin1.fromString $ concat
  [ "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com bigapp - - - "
  , "hey world"
  ]

ietfD :: Bytes
ietfD = Latin1.fromString $ concat
  [ "<38>1 2021-11-18T11:55:55.661764Z 192.0.2.20 SentinelOne "
  , "ab1fc131b2f29bc49b09286bb05e0b94e5c36610 1291980691205274618 "
  , "[fileName@53163 fileName=\"badcat.exe\"]"
  , "[deviceAddress@53163 deviceAddress=\"192.0.2.21\"]"
  , "[path@53163 path=\"\\\\foo\\\\bar.txt\"]"
  , " bad news"
  ]

ietfE :: Bytes
ietfE = Latin1.fromString $ concat
  [ "<14>1 2021-12-10T09:19:19.614-05:00 THE-HOST RT_FLOW - RT_FLOW_SESSION_DENY "
  , "[junos@2636.1.1.1.2.40 source-address=\"192.0.2.13\"]"
  ]

ietfF :: Bytes
ietfF = Latin1.fromString "<14>1 2023-05-09T16:21:33-04:00 192.0.2.5 - - - -  CEF:0"
