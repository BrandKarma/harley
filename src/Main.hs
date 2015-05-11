{-# LANGUAGE RankNTypes #-}
module Main where

import Control.Monad (when, join)
import Control.Monad.IO.Class
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Lazy as LB
import qualified Network.Pcap as P
import qualified Network.Pcap.Base as PB
import Data.Word (Word8, Word16)
import Data.Bits ((.&.), (.|.), shiftR, shiftL)
import qualified Foreign.Ptr as FFI
import qualified Foreign.Storable as FFI
import qualified Pipes as PI
import qualified Pipes.ByteString as PI
import Pipes ((>->))
import qualified Pipes.Network.TCP as PI
import qualified Pipes.HTTP as PI
import qualified Network.Simple.TCP as N
import Options.Applicative
import qualified  Network.URI as URI
import Data.Maybe (fromJust)
import qualified System.IO as SIO
import qualified Network.HTTP.Client as HTTP
import qualified Network.HTTP.Types.Status as HTTP
import qualified Network.HTTP.Client.TLS as HTTP
import qualified Control.Concurrent.Async as Async
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp as Warp

data ClientOptions = ClientOptions
  {
    clientOutput :: Maybe String
  }


data ServerOptions = ServerOptions
  {
    serverOutput :: String
  , serverInput :: String
  }


data Command = Server ServerOptions
             | Client ClientOptions


clientOptions :: Parser ClientOptions
clientOptions = ClientOptions
    <$> optional (strOption
        (  long "output"
        <> metavar "DEST"
        <> help "Destination server"
        ))


serverOptions :: Parser ServerOptions
serverOptions = ServerOptions
    <$> (strOption
        (  long "output"
        <> metavar "DEST"
        <> help "destination server"
        ))
    <*> (strOption
        (  long "input"
        <> metavar "ORG"
        <> help "listener"
        ))


main :: IO ()
main = do
    join $ execParser (info options (fullDesc <> progDesc "Relay HTTP traffic" <> header "harley - swiss army knife to replya http traffic"))
    where
        options :: Parser (IO ())
        options = subparser
            (  command "client" (info (runClient <$> clientOptions) (fullDesc <> progDesc "Relay HTTP traffic" <> header "harley - swiss army knife to replay http traffic")) 
            <> command "server" (info (runServer <$> serverOptions) (fullDesc <> progDesc "Relay HTTP traffic" <> header "harley - swiss army knife to replay http traffic")) 
            ) 


dispatch :: URI.URI -> P.PcapHandle -> IO ()
dispatch uri handle = do
    let scheme = URI.uriScheme uri
    case scheme of
        "tcp:" -> forwardTcp uri handle
        "file:" -> forwardFile uri handle
        "http:" -> forwardHttp uri handle
        _ -> error $ "protocol " ++ scheme ++ " not supported."
        

forwardFile :: URI.URI -> P.PcapHandle -> IO ()
forwardFile uri handle = do
    let filename = URI.uriPath uri
    let producer = fromPcapHandle handle
    SIO.withFile filename SIO.WriteMode $ \h -> do
        SIO.hSetBuffering h (SIO.BlockBuffering (Just 1024))
        PI.runEffect $ producer >-> (PI.toHandle h)


replayHttp :: HTTP.Request -> IO LB.ByteString
replayHttp http_req =
  if HTTP.secure http_req
    then
      HTTP.withManager HTTP.tlsManagerSettings $ \m ->
        PI.withHTTP http_req m $ \resp -> PI.toLazyM $ HTTP.responseBody resp
    else
      HTTP.withManager HTTP.defaultManagerSettings $ \m ->
        PI.withHTTP http_req m $ \resp -> PI.toLazyM $ HTTP.responseBody resp


mkBackendRequest :: Wai.Request -> String -> IO HTTP.Request
mkBackendRequest wai_req backend_host = do
  lbs_req_body <- Wai.lazyRequestBody wai_req 
  init_req <- HTTP.parseUrl backend_host
  let http_req = init_req { HTTP.path = (Wai.rawPathInfo wai_req)
                          , HTTP.queryString = (Wai.rawQueryString wai_req)
                          , HTTP.requestBody = HTTP.RequestBodyLBS (lbs_req_body)
                          } :: HTTP.Request
  return http_req


forwardHttp :: URI.URI -> P.PcapHandle -> IO ()
forwardHttp uri handle = undefined


forwardTcp :: URI.URI -> P.PcapHandle -> IO ()
forwardTcp uri handle = do
    let scheme = init $ URI.uriScheme $ uri
    let port = drop 1 $ URI.uriPort $ fromJust (URI.uriAuthority uri)
    let regName = URI.uriRegName $ fromJust (URI.uriAuthority uri)
    (sock, sockAddr) <- N.connectSock regName port
    let producer = fromPcapHandle handle
    PI.runEffect $ producer >-> (PI.toSocket sock)
    N.closeSock sock



reverseProxy :: [String] -> Wai.Application
reverseProxy backend_hosts wai_req respond = do 
  http_reqs <- mapM (mkBackendRequest wai_req) backend_hosts
  responses <- Async.mapConcurrently replayHttp http_reqs
  let lbs_resp = head responses
  respond $ Wai.responseLBS HTTP.status200 [] lbs_resp


runServer :: ServerOptions -> IO ()
runServer config = do
  case URI.parseURI (serverInput config) of
      Just uri -> do 
            let listenPort = read $ drop 1 $ URI.uriPort $ fromJust (URI.uriAuthority uri)
            let backends = [(serverOutput config)]
            Warp.run listenPort (reverseProxy backends)
      Nothing -> putStrLn "Invalid URI"


runClient :: ClientOptions-> IO ()
runClient config = do
    let device_name = "en0"
    network <- P.lookupNet device_name
    handle <- P.openLive device_name 65535 True 0
    P.setFilter handle "tcp dst port 8000" False (PB.netMask network)

    case (clientOutput config) of
                      Just maybeUri -> do
                                          case URI.parseURI maybeUri of
                                            Just uri -> dispatch uri handle
                                            Nothing -> putStrLn "Invalid URI"
                      Nothing -> putStrLn "No output specified"


toBS :: (Int, FFI.Ptr Word8) -> IO C8.ByteString
toBS (len, ptr) = do
    s <- BI.create (fromIntegral len) $ \p -> BI.memcpy p ptr (fromIntegral len)
    return s


fromPcapHandle :: MonadIO m => P.PcapHandle -> PI.Producer' C8.ByteString m ()
fromPcapHandle handle = go handle
    where
        go :: MonadIO m => P.PcapHandle -> PI.Producer' C8.ByteString m ()
        go handle = do
            (hdr, ptr) <- liftIO $ P.next handle 
            let ethernet_size = 14
            let ip_packet = FFI.plusPtr ptr ethernet_size
            ip_packet_first_byte <- liftIO $ FFI.peek ip_packet

            ip_packet_third_byte <- liftIO $ FFI.peekByteOff ip_packet 2
            ip_packet_fourth_byte <- liftIO $ FFI.peekByteOff ip_packet 3
            let ip_total_len = fromIntegral ( (((fromIntegral (ip_packet_third_byte :: Word8)) `shiftL` 8) .|. (fromIntegral (ip_packet_fourth_byte :: Word8))) :: Word16 )
            let ip_hdr_size = 4 * fromIntegral ((ip_packet_first_byte .&. 0x0F) :: Word8)

            when (ip_hdr_size < 20) $ return ()

            let tcp_packet = FFI.plusPtr ip_packet ip_hdr_size
            let tcp_payload_offset = FFI.plusPtr tcp_packet 12
            tcp_payload_offset_byte <- liftIO $ FFI.peek tcp_payload_offset
            let tcp_hdr_size = 4 * fromIntegral (shiftR ((tcp_payload_offset_byte .&. 0xF0) :: Word8) 4)
            let tcp_payload = FFI.plusPtr tcp_packet tcp_hdr_size
            liftIO $ putStrLn $ "IP header size: " ++ (show ip_hdr_size)
            liftIO $ putStrLn $ "IP total len: " ++ (show ip_total_len)
            liftIO $ putStrLn $ "TCP header size: " ++ (show tcp_hdr_size)

            let payload_size = ip_total_len - ip_hdr_size - tcp_hdr_size

            when (payload_size > 0) $ do
                bs <- liftIO $ toBS (payload_size, tcp_payload)
                PI.yield bs

            go handle
