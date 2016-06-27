-----------------------------------------------------------------------------
-- |
-- Module      :  Main
-- Copyright   :  dramforever (c) 2016
-- License     :  BSD-style (see the file LICENSE)
-- Maintainer  :  dramforever <dramforever@live.com>
-- Stability   :  experimental
-- Portability :  non-portable
--
-- Usage: [stub]
-----------------------------------------------------------------------------
module Main where

import System.Environment
import qualified Data.ByteString.Char8 as B
import System.IO

import Asunr.Runner

main :: IO ()
main = getArgs >>= \x -> 
  case x of
    [arg, inf, outf] ->
      let r =
            withBinaryFile inf ReadMode $ \inh ->
            withBinaryFile outf WriteMode $ \outh ->
              let sc = SandboxConfig
                    { scProgram = B.pack arg
                    , scInputHandle = Just inh
                    , scOutputHandle = Just outh
                    , scTimeLimit = Just 10000
                    , scMemoryLimit = Just (128 * 1024)
                    }
              in runSandboxed sc >>= print
       in r >> r >> r
    _ -> putStrLn "Usage: asunr <program> <input-file> <output-file>"
