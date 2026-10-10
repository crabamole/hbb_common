use crate::{
    config::{
        use_ws, Config, Socks5Server, RENDEZVOUS_PORT,
    },
    protobuf::Message,
    socket_client::split_host_port,
    sodiumoxide::crypto::secretbox::Key,
    tcp::Encrypt,
    tls::{get_cached_tls_accept_invalid_cert, get_cached_tls_type, upsert_tls_cache, TlsType},
    ResultType,
};
use anyhow::bail;
use async_recursion::async_recursion;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_native_tls::native_tls::TlsConnector;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::protocol::Message as WsMessage, Connector,
    MaybeTlsStream, WebSocketStream,
};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::Role;

pub struct WsFramedStream {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    addr: SocketAddr,
    encrypt: Option<Encrypt>,
    send_timeout: u64,
}

impl WsFramedStream {
    #[inline]
    fn get_connector(
        tls_type: &TlsType,
        danger_accept_invalid_certs: bool,
    ) -> ResultType<Option<Connector>> {
        match tls_type {
            TlsType::Plain => Ok(Some(Connector::Plain)),
            TlsType::NativeTls => {
                let connector = TlsConnector::builder()
                    .danger_accept_invalid_certs(danger_accept_invalid_certs)
                    .build()?;
                Ok(Some(Connector::NativeTls(connector)))
            }
            TlsType::Rustls => {
                let connector = match crate::verifier::client_config(danger_accept_invalid_certs) {
                    Ok(client_config) => Some(Connector::Rustls(Arc::new(client_config))),
                    Err(e) => {
                        log::warn!(
                            "Failed to get client config: {:?}, fallback to default connector",
                            e
                        );
                        None
                    }
                };
                Ok(connector)
            }
        }
    }

    async fn connect(
        url: &str,
        ms_timeout: u64,
    ) -> ResultType<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        // to-do: websocket proxy.

        let tls_type = get_cached_tls_type(url);
        let is_tls_type_cached = tls_type.is_some();
        let tls_type = tls_type.unwrap_or(TlsType::Rustls);
        let danger_accept_invalid_cert = get_cached_tls_accept_invalid_cert(&url);
        Self::try_connect(
            url,
            ms_timeout,
            tls_type,
            is_tls_type_cached,
            danger_accept_invalid_cert,
            danger_accept_invalid_cert,
        )
        .await
    }

    #[async_recursion]
    async fn try_connect(
        url: &str,
        ms_timeout: u64,
        tls_type: TlsType,
        is_tls_type_cached: bool,
        danger_accept_invalid_cert: Option<bool>,
        original_danger_accept_invalid_certs: Option<bool>,
    ) -> ResultType<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let ws_config = None;
        let disable_nagle = false;
        let request = url
            .into_client_request()
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        let connector =
            Self::get_connector(&tls_type, danger_accept_invalid_cert.unwrap_or(false))?;
        match timeout(
            Duration::from_millis(ms_timeout),
            connect_async_tls_with_config(request, ws_config, disable_nagle, connector),
        )
        .await?
        {
            Ok((ws_stream, _)) => {
                upsert_tls_cache(url, tls_type, danger_accept_invalid_cert.unwrap_or(false));
                Ok(ws_stream)
            }
            Err(e) => match (tls_type, is_tls_type_cached, danger_accept_invalid_cert) {
                (TlsType::Rustls, _, None) => {
                    log::warn!(
                            "WebSocket connection with rustls-tls failed, try accept invalid certs: {}, {:?}",
                            url,
                            e
                        );
                    Self::try_connect(
                        url,
                        ms_timeout,
                        tls_type,
                        is_tls_type_cached,
                        Some(true),
                        original_danger_accept_invalid_certs,
                    )
                    .await
                }
                (TlsType::Rustls, false, Some(_)) => {
                    log::warn!(
                        "WebSocket connection with rustls-tls failed, try native-tls: {}, {:?}",
                        url,
                        e
                    );
                    Self::try_connect(
                        url,
                        ms_timeout,
                        TlsType::NativeTls,
                        is_tls_type_cached,
                        original_danger_accept_invalid_certs,
                        original_danger_accept_invalid_certs,
                    )
                    .await
                }
                (TlsType::NativeTls, _, None) => {
                    log::warn!(
                            "WebSocket connection with native-tls failed, try accept invalid certs: {}, {:?}",
                            url,
                            e
                        );
                    Self::try_connect(
                        url,
                        ms_timeout,
                        tls_type,
                        is_tls_type_cached,
                        Some(true),
                        original_danger_accept_invalid_certs,
                    )
                    .await
                }
                _ => {
                    log::error!(
                        "WebSocket connection failed with tls_type {:?}: {}, {:?}",
                        tls_type,
                        url,
                        e
                    );
                    if let tungstenite::Error::Http(response) = &e {
                        if response.status().is_redirection() {
                            bail!(
                                "WebSocket connection failed ({}). The server may not support WebSocket.",
                                e
                            )
                        }
                    }
                    bail!("WebSocket error: {}", e)
                }
            },
        }
    }

    pub async fn new<T: AsRef<str>>(
        url: T,
        _local_addr: Option<SocketAddr>,
        _proxy_conf: Option<&Socks5Server>,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        let stream = Self::connect(url.as_ref(), ms_timeout).await?;
        let addr = match stream.get_ref() {
            MaybeTlsStream::Plain(tcp) => tcp.peer_addr()?,
            MaybeTlsStream::NativeTls(tls) => tls.get_ref().get_ref().get_ref().peer_addr()?,
            MaybeTlsStream::Rustls(tls) => tls.get_ref().0.peer_addr()?,
            _ => return Err(Error::new(ErrorKind::Other, "Unsupported stream type").into()),
        };

        let ws = Self {
            stream,
            addr,
            encrypt: None,
            send_timeout: ms_timeout,
        };

        Ok(ws)
    }

    #[inline]
    pub fn set_raw(&mut self) {
        self.encrypt = None;
    }

    #[inline]
    pub async fn from_tcp_stream(stream: TcpStream, addr: SocketAddr) -> ResultType<Self> {
        let ws_stream =
            WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(stream), Role::Client, None)
                .await;

        Ok(Self {
            stream: ws_stream,
            addr,
            encrypt: None,
            send_timeout: 0,
        })
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    #[inline]
    pub fn set_send_timeout(&mut self, ms: u64) {
        self.send_timeout = ms;
    }

    #[inline]
    pub fn set_key(&mut self, key: Key) {
        self.encrypt = Some(Encrypt::new(key));
    }

    #[inline]
    pub fn is_secured(&self) -> bool {
        self.encrypt.is_some()
    }

    #[inline]
    pub async fn send(&mut self, msg: &impl Message) -> ResultType<()> {
        self.send_raw(msg.write_to_bytes()?).await
    }

    #[inline]
    pub async fn send_raw(&mut self, msg: Vec<u8>) -> ResultType<()> {
        let mut msg = msg;
        if let Some(key) = self.encrypt.as_mut() {
            msg = key.enc(&msg);
        }
        self.send_bytes(Bytes::from(msg)).await
    }

    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        let msg = WsMessage::Binary(bytes);
        if self.send_timeout > 0 {
            timeout(
                Duration::from_millis(self.send_timeout),
                self.stream.send(msg),
            )
            .await??
        } else {
            self.stream.send(msg).await?
        };
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        while let Some(msg) = self.stream.next().await {
            let msg = match msg {
                Ok(msg) => msg,
                Err(e) => {
                    log::error!("{}", e);
                    return Some(Err(Error::new(
                        ErrorKind::Other,
                        format!("WebSocket protocol error: {}", e),
                    )));
                }
            };

            match msg {
                WsMessage::Binary(data) => {
                    let mut bytes = BytesMut::from(&data[..]);
                    if let Some(key) = self.encrypt.as_mut() {
                        if let Err(err) = key.dec(&mut bytes) {
                            return Some(Err(err));
                        }
                    }
                    return Some(Ok(bytes));
                }
                WsMessage::Text(text) => {
                    let bytes = BytesMut::from(text.as_bytes());
                    return Some(Ok(bytes));
                }
                WsMessage::Close(_) => {
                    return None;
                }
                _ => {
                    continue;
                }
            }
        }

        None
    }

    #[inline]
    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<BytesMut, Error>> {
        match timeout(Duration::from_millis(ms), self.next()).await {
            Ok(res) => res,
            Err(_) => None,
        }
    }
}

pub fn is_ws_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with("ws://") || endpoint.starts_with("wss://")
}

/**
 * Core function to convert an endpoint to WebSocket format
 *
 * Converts between different address formats:
 * 1. IPv4 address with/without port -> ws://ipv4:port
 * 2. IPv6 address with/without port -> ws://[ipv6]:port
 * 3. Domain with/without port -> ws(s)://domain/ws/id
 *
 * @param endpoint The endpoint to convert
 * @return The converted WebSocket endpoint
 */
pub fn check_ws(endpoint: &str) -> String {
    if !use_ws() {
        return endpoint.to_string();
    }

    if endpoint.is_empty() {
        return endpoint.to_string();
    }

    if is_ws_endpoint(endpoint) {
        return endpoint.to_string();
    }

    let Some((endpoint_host, endpoint_port)) = split_host_port(endpoint) else {
        debug_assert!(false, "endpoint doesn't have port");
        return endpoint.to_string();
    };

    let custom_rendezvous_server = Config::get_rendezvous_server();
    let rendezvous_port = split_host_port(&custom_rendezvous_server)
        .map(|(_, p)| p)
        .unwrap_or(RENDEZVOUS_PORT);

    // Only hbbs is dialed from a host:port; relays are always ws(s) URLs.
    let dst_port = if endpoint_port == rendezvous_port - 1 {
        // online
        endpoint_port + 3
    } else {
        endpoint_port + 2
    };

    let (address, is_domain) = if crate::is_ip_str(endpoint) {
        (format!("{}:{}", endpoint_host, dst_port), false)
    } else {
        if let Some(origin) = ws_origin_from_api_server(&endpoint_host, endpoint_port) {
            return format!("{}/ws/id", origin);
        }
        (format!("{}/ws/id", endpoint_host), true)
    };
    let protocol = if is_domain {
        let api_server = Config::get_option("api-server");
        if api_server.starts_with("https") {
            "wss"
        } else {
            "ws"
        }
    } else {
        "ws"
    };
    format!("{}://{}", protocol, address)
}

// The WebSocket proxy is served from the api-server origin when the endpoint names that same
// host:port, or derives from a rendezvous server that does (online port-1).
fn ws_origin_from_api_server(host: &str, endpoint_port: i32) -> Option<String> {
    let api = url::Url::parse(&Config::get_option("api-server")).ok()?;
    let api_host = api.host_str()?;
    if !api_host.eq_ignore_ascii_case(host) {
        return None;
    }
    let api_port = api.port_or_known_default()? as i32;
    let derived = split_host_port(Config::get_rendezvous_server()).map_or(false, |(h, p)| {
        h.eq_ignore_ascii_case(api_host)
            && p == api_port
            && endpoint_port == p - 1
    });
    if (RENDEZVOUS_PORT - 1..=RENDEZVOUS_PORT + 2).contains(&endpoint_port)
        || (endpoint_port != api_port && !derived)
    {
        return None;
    }
    let scheme = match api.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => return None,
    };
    Some(match api.port() {
        Some(port) => format!("{}://{}:{}", scheme, host, port),
        None => format!("{}://{}", scheme, host),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{keys, Config};

    // Both tests mutate the global config.
    static CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_check_ws() {
        let _lock = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // enable websocket
        Config::set_option(keys::OPTION_ALLOW_WEBSOCKET.to_string(), "Y".to_string());

        // not set custom-rendezvous-server
        Config::set_option("custom-rendezvous-server".to_string(), "".to_string());
        Config::set_option("api-server".to_string(), "".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("rustdesk.com:21115"), "ws://rustdesk.com/ws/id");
        assert_eq!(check_ws("rustdesk.com:21116"), "ws://rustdesk.com/ws/id");
        // a former relay port is not mapped to a relay path
        assert_eq!(check_ws("rustdesk.com:21117"), "ws://rustdesk.com/ws/id");
        Config::set_option(
            "api-server".to_string(),
            "https://api.rustdesk.com".to_string(),
        );
        assert_eq!(
            check_ws("[0:0:0:0:0:0:0:1]:21115"),
            "ws://[0:0:0:0:0:0:0:1]:21118"
        );
        assert_eq!(
            check_ws("[0:0:0:0:0:0:0:1]:21116"),
            "ws://[0:0:0:0:0:0:0:1]:21118"
        );
        assert_eq!(check_ws("rustdesk.com:21115"), "wss://rustdesk.com/ws/id");
        assert_eq!(check_ws("rustdesk.com:21116"), "wss://rustdesk.com/ws/id");
        // relay URLs from hbbs pass through
        assert_eq!(
            check_ws("wss://rustdesk.com/ws/relay/1"),
            "wss://rustdesk.com/ws/relay/1"
        );

        // set custom-rendezvous-server without port
        Config::set_option(
            "custom-rendezvous-server".to_string(),
            "127.0.0.1".to_string(),
        );
        Config::set_option("api-server".to_string(), "".to_string());
        assert_eq!(check_ws("127.0.0.1:21115"), "ws://127.0.0.1:21118");
        assert_eq!(check_ws("127.0.0.1:21116"), "ws://127.0.0.1:21118");

        // set custom-rendezvous-server with custom port
        Config::set_option(
            "custom-rendezvous-server".to_string(),
            "127.0.0.1:23456".to_string(),
        );
        assert_eq!(check_ws("127.0.0.1:23455"), "ws://127.0.0.1:23458");
        assert_eq!(check_ws("127.0.0.1:23456"), "ws://127.0.0.1:23458");
    }

    #[test]
    fn test_check_ws_api_server_origin() {
        let _lock = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let set = |k: &str, v: &str| Config::set_option(k.to_string(), v.to_string());
        set(keys::OPTION_ALLOW_WEBSOCKET, "Y");

        // endpoint without port / default ports: unchanged even if api-server has a port
        set("custom-rendezvous-server", "host.test");
        set("api-server", "http://host.test:21114");
        assert_eq!(check_ws("host.test:21116"), "ws://host.test/ws/id");
        assert_eq!(check_ws("host.test:21115"), "ws://host.test/ws/id");
        set("api-server", "http://host.test:18080");
        assert_eq!(check_ws("host.test:21116"), "ws://host.test/ws/id");

        // endpoint carries the api-server port
        set("custom-rendezvous-server", "host.test:18080");
        set("api-server", "http://host.test:18080");
        assert_eq!(check_ws("host.test:18080"), "ws://host.test:18080/ws/id");
        assert_eq!(check_ws("HOST.test:18080"), "ws://HOST.test:18080/ws/id");
        // online (port-1) derives from the rendezvous server
        assert_eq!(check_ws("host.test:18079"), "ws://host.test:18080/ws/id");
        // port+1 is no longer a derived relay
        assert_eq!(check_ws("host.test:18081"), "ws://host.test/ws/id");
        // rendezvous server on another host: derived ports do not apply
        set("custom-rendezvous-server", "other.test:18080");
        assert_eq!(check_ws("host.test:18079"), "ws://host.test/ws/id");
        assert_eq!(check_ws("host.test:18080"), "ws://host.test:18080/ws/id");

        // https api-server with explicit port
        set("custom-rendezvous-server", "host.test:8443");
        set("api-server", "https://host.test:8443/");
        assert_eq!(check_ws("host.test:8443"), "wss://host.test:8443/ws/id");
        assert_eq!(check_ws("host.test:8442"), "wss://host.test:8443/ws/id");
        // endpoint port differs from api-server port and rendezvous port: unchanged
        set("custom-rendezvous-server", "host.test:30000");
        assert_eq!(check_ws("host.test:30000"), "wss://host.test/ws/id");

        // rendezvous host:443
        set("custom-rendezvous-server", "host.test:443");
        set("api-server", "https://host.test");
        assert_eq!(check_ws("host.test:443"), "wss://host.test/ws/id");

        // api-server on another host: unchanged
        set("custom-rendezvous-server", "rustdesk.com:18080");
        set("api-server", "https://api.rustdesk.com:18080");
        assert_eq!(check_ws("rustdesk.com:18080"), "wss://rustdesk.com/ws/id");

        // IP endpoints: unchanged, even when api-server names the same IP and port
        set("custom-rendezvous-server", "127.0.0.1:18080");
        set("api-server", "http://127.0.0.1:18080");
        assert_eq!(check_ws("127.0.0.1:18080"), "ws://127.0.0.1:18082");
        assert_eq!(check_ws("127.0.0.1:18079"), "ws://127.0.0.1:18082");

        // no api-server: unchanged
        set("custom-rendezvous-server", "");
        set("api-server", "");
        assert_eq!(check_ws("rustdesk.com:21116"), "ws://rustdesk.com/ws/id");

        // websocket disabled: endpoint passed through
        set(keys::OPTION_ALLOW_WEBSOCKET, "");
        assert_eq!(check_ws("rustdesk.com:21116"), "rustdesk.com:21116");
    }
}
