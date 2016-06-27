{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE LambdaCase #-}
-----------------------------------------------------------------------------
-- |
-- Module      :  Asunr.Runner
-- Copyright   :  dramforever (c) 2016
-- License     :  BSD-style (see the file LICENSE)
-- Maintainer  :  dramforever <dramforever@live.com>
-- Stability   :  experimental
-- Portability :  non-portable
--
-- Usage: [stub]
-----------------------------------------------------------------------------

module Asunr.Runner where

import Foreign.C.Types
import Foreign.Ptr
import Foreign.C.String
import Data.Int
import qualified Data.ByteString as B
import System.Exit
import System.Posix.Process
import System.Posix.IO
import System.Posix.Types
import System.Posix.Process.Internals (decipherWaitStatus)
import Foreign.Marshal
import Foreign.Storable
import GHC.Conc (Signal)
import System.IO
foreign import ccall "run_sandboxed"
  c_run_sandboxed :: CString -> CInt -> CInt
                  -> CLong -> CLong
                  -> Ptr CLong -> Ptr CLong
                  -> IO CInt

data SandboxConfig
  = SandboxConfig
    { scProgram :: B.ByteString
    , scInputHandle :: Maybe Handle
    , scOutputHandle :: Maybe Handle
    , scTimeLimit :: Maybe Int64
    , scMemoryLimit :: Maybe Int64
    }

data SandboxStatus
  = SandboxExited ExitCode
  | SandboxTLE
  | SandboxMLE
  | SandboxOtherSignal Signal
  deriving (Show)

data SandboxResult
  = SandboxInternalError
  | SandboxResult
    { srStatus :: SandboxStatus
    , srCpuTime :: Int64
    , srMaxRss :: Int64
    }
  deriving (Show)

runSandboxed :: SandboxConfig -> IO SandboxResult
runSandboxed SandboxConfig{..} =
  alloca $ \pCpu ->
  alloca $ \pMem ->
  B.useAsCString scProgram $ \sProg -> do
    let conv Nothing = -1
        conv (Just x) = fromIntegral x

        getFd (Just ih) = (\case Fd x -> x) <$> handleToFd ih
        getFd Nothing = pure (-1)

    inFd <- getFd scInputHandle
    outFd <- getFd scOutputHandle
    
    status <- c_run_sandboxed
      sProg inFd outFd
      (conv scTimeLimit) (conv scMemoryLimit)
      pCpu pMem
    if status >= 0
      then do                              
        ws <- decipherWaitStatus status
        cpu <- peek pCpu
        mem <- peek pMem
        let explainedStatus =
              case ws of
                Exited ec -> SandboxExited ec
                Terminated 14 _ -> SandboxTLE
                Terminated 11 _
                  | Just ml <- scMemoryLimit
                    , fromIntegral mem > ml -> SandboxMLE
                  | otherwise -> SandboxOtherSignal 11
                Terminated sig _ -> SandboxOtherSignal sig
                Stopped _ -> error "Unexpected stop"

        case ws of
          Terminated 10 _ ->
            pure SandboxInternalError
          _ ->
            pure SandboxResult
              { srStatus = explainedStatus
              , srCpuTime = fromIntegral cpu
              , srMaxRss = fromIntegral mem
              }
      else pure SandboxInternalError
