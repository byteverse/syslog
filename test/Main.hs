{-# language DuplicateRecordFields #-}
{-# language NamedFieldPuns #-}

import Data.Bytes (Bytes)
import Syslog.Bsd (Message(Message),Process(Process))

import qualified Data.Bytes as Bytes
import qualified Syslog.Bsd as Bsd

main :: IO ()
main = do
  putStrLn "Starting"
  putStrLn "Test A"
  case Bsd.decode msgA of
    Nothing -> fail "Could not decode message A"
    Just Message{priority,hostname,process=Process{name},message} -> do
      assert "priority" (priority == 133)
      assert "hostname" (hostname == Bytes.fromLatinString "webserver")
      assert "process_name" (name == Bytes.fromLatinString "syslogd")
      assert "message" (message == Bytes.fromLatinString "restart")
  putStrLn "Test B"
  case Bsd.decode msgB of
    Nothing -> fail "Could not decode message B"
    Just Message{priority,hostname,process=Process{name},message} -> do
      assert "priority" (priority == 0)
      assert "hostname" (hostname == Bytes.fromLatinString "foo.example.org")
      assert "process_name" (name == Bytes.fromLatinString "sched")
      assert "message" (message == Bytes.fromLatinString "That's all")
  putStrLn "Test C"
  case Bsd.decode msgC of
    Nothing -> fail "Could not decode message C"
    Just Message{priority,hostname,process=Process{name},message} -> do
      assert "priority" (priority == 133)
      assert "hostname" (hostname == Bytes.fromLatinString "192.0.2.231")
      assert "process_name" (name == Bytes.fromLatinString "stm")
      assert "message" (message == Bytes.fromLatinString "Hello")
  putStrLn "Finished"

assert :: String -> Bool -> IO ()
assert ctx b = if b then pure () else fail ctx

msgA, msgB, msgC :: Bytes
msgA = Bytes.fromLatinString "<133>Feb 25 14:09:07 webserver syslogd: restart"
msgB = Bytes.fromLatinString "<0>Oct 22 10:52:01 foo.example.org sched[0]: That's all"
msgC = Bytes.fromLatinString "<133>May  2 11:43:37 2020 192.0.2.231 stm[8753]:  Hello"
