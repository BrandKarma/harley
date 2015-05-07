module Main where

import Control.Monad (when)
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Internal as BI
import qualified Network.Pcap as P
import qualified Network.Pcap.Base as PB
import Data.Word (Word8, Word16)
import Data.Bits ((.&.), (.|.), shiftR, shiftL)
import qualified Foreign.Ptr as FFI
import qualified Foreign.Storable as FFI


main :: IO ()
main = do
  let device_name = "en0"
  network <- P.lookupNet device_name
  handle <- P.openLive device_name 65535 True 0
  P.setFilter handle "tcp port 8000" False (PB.netMask network)
  nPkt <- P.loop handle (-1) process
  print nPkt


toBS :: (Int, FFI.Ptr Word8) -> IO C8.ByteString
toBS (len, ptr) = do
    s <- BI.create (fromIntegral len) $ \p -> BI.memcpy p ptr (fromIntegral len)
    return s


process :: P.PktHdr -> FFI.Ptr Word8 -> IO ()
process hdr ptr = do
  let ethernet_size = 14
  let ip_packet = FFI.plusPtr ptr ethernet_size
  ip_packet_first_byte <- (FFI.peek ip_packet)

  ip_packet_third_byte <- (FFI.peekByteOff ip_packet 2)
  ip_packet_fourth_byte <- (FFI.peekByteOff ip_packet 3)
  let ip_total_len = fromIntegral ( (((fromIntegral (ip_packet_third_byte :: Word8)) `shiftL` 8) .|. (fromIntegral (ip_packet_fourth_byte :: Word8))) :: Word16 )
  let ip_hdr_size = 4 * fromIntegral ((ip_packet_first_byte .&. 0x0F) :: Word8)

  when (ip_hdr_size < 20) $ return ()

  let tcp_packet = FFI.plusPtr ip_packet ip_hdr_size
  let tcp_payload_offset = FFI.plusPtr tcp_packet 12
  tcp_payload_offset_byte <- FFI.peek tcp_payload_offset
  let tcp_hdr_size = 4 * fromIntegral (shiftR ((tcp_payload_offset_byte .&. 0xF0) :: Word8) 4)
  let tcp_payload = FFI.plusPtr tcp_packet tcp_hdr_size
  putStrLn $ "IP header size: " ++ (show ip_hdr_size)
  putStrLn $ "IP total len: " ++ (show ip_total_len)
  putStrLn $ "TCP header size: " ++ (show tcp_hdr_size)

  let payload_size = ip_total_len - ip_hdr_size - tcp_hdr_size

  when (payload_size > 0) $ do
    bs <- toBS (payload_size, tcp_payload)
    C8.putStrLn bs
