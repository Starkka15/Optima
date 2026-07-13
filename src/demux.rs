//! Ubisoft Connect Demux client (`dmx.upc.ubisoft.com`).
//!
//! Demux is a length-prefixed protobuf protocol over TLS — NOT behind DataDome,
//! so a browser-captured `ubi_v1` ticket authenticates fine here. Wire format:
//! each message is a 4-byte big-endian length followed by a serialized
//! `Upstream` (client→server) or `Downstream` (server→client). Flow:
//!   1. `AuthenticateReq { token.ubi_ticket, client_id: "uplay_pc" }`
//!   2. `OpenConnectionReq { service_name: "ownership_service" }` → connection_id
//!   3. send the ownership service's own `Upstream{ Req{ initialize_req } }` as a
//!      `DataMessage` on that connection; read back the `InitializeRsp`.

use anyhow::{anyhow, bail, Context, Result};
use prost::Message;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::proto::{demux, ownership};

const DEMUX_HOST: &str = "dmx.upc.ubisoft.com";
const DEMUX_PORT: u16 = 443;
/// The client id the PC launcher authenticates as.
const CLIENT_ID: &str = "uplay_pc";
/// Ubisoft Connect launcher build number reported to demux (the 4th component of
/// the launcher version, e.g. 172.1.0.**13247**). MUST be sent first on a fresh
/// socket, and must be recent enough or the server replies ClientOutdatedPush
/// and drops the connection. Bump this to the current launcher build over time.
const API_VERSION: u32 = 13247;

pub struct Demux {
    tls: TlsStream<TcpStream>,
    next_request_id: u32,
}

impl Demux {
    /// TLS-connect and authenticate with a `ubi_v1` ticket.
    pub async fn connect(ticket: &str) -> Result<Self> {
        // Ensure a rustls crypto provider is installed (ring).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = TcpStream::connect((DEMUX_HOST, DEMUX_PORT))
            .await
            .with_context(|| format!("connecting to {DEMUX_HOST}:{DEMUX_PORT}"))?;
        let server_name = rustls::pki_types::ServerName::try_from(DEMUX_HOST)
            .context("invalid server name")?
            .to_owned();
        let tls = connector.connect(server_name, tcp).await.context("TLS handshake")?;

        let mut demux = Demux {
            tls,
            next_request_id: 1,
        };
        // Mandatory first message: the client version handshake (fire-and-forget
        // push). Without it the server drops the connection on our next frame.
        demux.send_client_version().await?;
        demux.authenticate(ticket).await?;
        Ok(demux)
    }

    fn request_id(&mut self) -> u32 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    async fn write_upstream(&mut self, msg: &demux::Upstream) -> Result<()> {
        let body = msg.encode_to_vec();
        let len = u32::try_from(body.len()).context("message too large")?;
        self.tls.write_all(&len.to_be_bytes()).await?;
        self.tls.write_all(&body).await?;
        self.tls.flush().await?;
        Ok(())
    }

    async fn read_downstream(&mut self) -> Result<demux::Downstream> {
        let fut = async {
            let mut len_buf = [0u8; 4];
            self.tls.read_exact(&mut len_buf).await.context("reading frame length")?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            self.tls.read_exact(&mut body).await.context("reading frame body")?;
            demux::Downstream::decode(&body[..]).context("decoding Downstream")
        };
        match tokio::time::timeout(std::time::Duration::from_secs(15), fut).await {
            Ok(res) => res,
            Err(_) => bail!("timed out waiting for a Demux response"),
        }
    }

    /// Read frames until the response with `request_id` arrives, skipping the
    /// keep-alive / version / product pushes the server interleaves.
    async fn read_response(&mut self, request_id: u32) -> Result<demux::Rsp> {
        for _ in 0..32 {
            let down = self.read_downstream().await?;
            if std::env::var_os("OPTIMA_DEBUG").is_some() {
                eprintln!("[demux frame] {down:?}");
            }
            if let Some(rsp) = down.response {
                if rsp.request_id == request_id {
                    return Ok(rsp);
                }
            }
        }
        bail!("no response for request {request_id} after 32 frames")
    }

    async fn send_client_version(&mut self) -> Result<()> {
        let up = demux::Upstream {
            push: Some(demux::Push {
                client_version: Some(demux::ClientVersionPush {
                    version: API_VERSION,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.write_upstream(&up).await
    }

    async fn authenticate(&mut self, ticket: &str) -> Result<()> {
        let req = demux::Upstream {
            request: Some(demux::Req {
                request_id: self.request_id(),
                authenticate_req: Some(demux::AuthenticateReq {
                    token: demux::Token {
                        ubi_ticket: Some(ticket.to_string()),
                        ..Default::default()
                    },
                    client_id: Some(CLIENT_ID.to_string()),
                    send_keep_alive: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let id = req.request.as_ref().unwrap().request_id;
        self.write_upstream(&req).await?;

        let rsp = self.read_response(id).await?;
        let auth = rsp
            .authenticate_rsp
            .ok_or_else(|| anyhow!("no authenticate_rsp in response"))?;
        if !auth.success {
            bail!(
                "authentication failed (expired={:?}, banned={:?}) — re-run `optima-cli login`",
                auth.expired,
                auth.banned
            );
        }
        Ok(())
    }

    pub async fn open_connection(&mut self, service_name: &str) -> Result<u32> {
        let req = demux::Upstream {
            request: Some(demux::Req {
                request_id: self.request_id(),
                open_connection_req: Some(demux::OpenConnectionReq {
                    service_name: service_name.to_string(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let id = req.request.as_ref().unwrap().request_id;
        self.write_upstream(&req).await?;

        let rsp = self.read_response(id).await?;
        let open = rsp
            .open_connection_rsp
            .ok_or_else(|| anyhow!("no open_connection_rsp for {service_name}"))?;
        if !open.success {
            bail!("service {service_name} refused the connection");
        }
        Ok(open.connection_id)
    }

    /// Send a service payload on a connection (wrapped in a DataMessage push) and
    /// read the matching DataMessage back, returning its raw bytes.
    pub async fn service_call(&mut self, connection_id: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        self.service_roundtrip(connection_id, payload).await
    }

    async fn service_roundtrip(&mut self, connection_id: u32, payload: Vec<u8>) -> Result<Vec<u8>> {
        // The inner service payload is itself 4-byte-big-endian length-prefixed
        // *inside* the DataMessage, and responses come back the same way.
        let mut framed = Vec::with_capacity(payload.len() + 4);
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(&payload);

        let up = demux::Upstream {
            push: Some(demux::Push {
                data: Some(demux::DataMessage {
                    connection_id,
                    data: framed,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.write_upstream(&up).await?;

        // Services may interleave keep-alive / version pushes; read until we get
        // a DataMessage for our connection, then strip its length prefix.
        for _ in 0..16 {
            let down = self.read_downstream().await?;
            if std::env::var_os("OPTIMA_DEBUG").is_some() {
                eprintln!(
                    "[svc frame] want_conn={connection_id} resp={} push_data_conn={:?}",
                    down.response.is_some(),
                    down.push.as_ref().and_then(|p| p.data.as_ref()).map(|d| d.connection_id)
                );
            }
            if let Some(push) = down.push {
                if let Some(data) = push.data {
                    if data.connection_id == connection_id {
                        let inner = if data.data.len() >= 4 {
                            data.data[4..].to_vec()
                        } else {
                            data.data
                        };
                        return Ok(inner);
                    }
                }
            }
        }
        bail!("no data response on connection {connection_id}")
    }

    /// Fetch the current manifest id for a product whose `latest_manifest` field
    /// was absent in the ownership listing (newer titles omit it). Uses the
    /// ownership service's `GetLatestManifests` (still wired despite the name).
    pub async fn get_latest_manifest(&mut self, product_id: u32) -> Result<Option<String>> {
        let conn = self.open_connection("ownership_service").await?;
        // Init the connection first, as every ownership call requires.
        let init = ownership::Upstream {
            request: Some(ownership::Req {
                request_id: 1,
                initialize_req: Some(ownership::InitializeReq {
                    get_associations: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let _ = self.service_roundtrip(conn, init.encode_to_vec()).await?;

        let up = ownership::Upstream {
            request: Some(ownership::Req {
                request_id: 2,
                deprecated_get_latest_manifests_req: Some(ownership::DeprecatedGetLatestManifestsReq {
                    deprecated_product_ids: vec![product_id],
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let raw = self.service_roundtrip(conn, up.encode_to_vec()).await?;
        let down = ownership::Downstream::decode(&raw[..])
            .context("decoding GetLatestManifests rsp")?;
        if std::env::var_os("OPTIMA_DEBUG").is_some() {
            eprintln!("[manifest rsp] {} bytes raw; decoded: {down:?}", raw.len());
        }
        Ok(down
            .response
            .and_then(|r| r.deprecated_get_latest_manifests_rsp)
            .and_then(|r| {
                r.manifests
                    .into_iter()
                    .find(|m| m.product_id == product_id)
                    .and_then(|m| m.manifest)
            })
            .filter(|m| !m.is_empty()))
    }

    /// Fetch a real `uplay_pc_ticket` for a game (by its uplay_id) — the token
    /// the Uplay SDK hands the game. Backs our reimplemented loader's
    /// `UPLAY_USER_GetTicketUtf8` so launches are ownership-backed, not spoofed.
    pub async fn get_uplay_pc_ticket(&mut self, uplay_id: u32) -> Result<Option<String>> {
        let conn = self.open_connection("ownership_service").await?;
        let init = ownership::Upstream {
            request: Some(ownership::Req {
                request_id: 1,
                initialize_req: Some(ownership::InitializeReq {
                    get_associations: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let _ = self.service_roundtrip(conn, init.encode_to_vec()).await?;

        let up = ownership::Upstream {
            request: Some(ownership::Req {
                request_id: 2,
                get_uplay_pc_ticket_req: Some(ownership::GetUplayPcTicketReq {
                    uplay_id,
                    platform: None,
                }),
                ..Default::default()
            }),
        };
        let raw = self.service_roundtrip(conn, up.encode_to_vec()).await?;
        let down = ownership::Downstream::decode(&raw[..]).context("decoding uplay ticket rsp")?;
        Ok(down
            .response
            .and_then(|r| r.get_uplay_pc_ticket_rsp)
            .filter(|t| t.success)
            .and_then(|t| t.uplay_pc_ticket))
    }

    /// Batch-resolve manifests for many products in a SINGLE ownership call.
    /// Returns only the ids that have a real Ubisoft CDN build (a non-empty
    /// manifest) — Steam-linked / delisted copies come back `ServerError` and are
    /// omitted. Used to decide which owned games are actually installable.
    pub async fn get_latest_manifests(
        &mut self,
        product_ids: &[u32],
    ) -> Result<std::collections::HashMap<u32, String>> {
        use std::collections::HashMap;
        let mut out = HashMap::new();
        if product_ids.is_empty() {
            return Ok(out);
        }
        let conn = self.open_connection("ownership_service").await?;
        let init = ownership::Upstream {
            request: Some(ownership::Req {
                request_id: 1,
                initialize_req: Some(ownership::InitializeReq {
                    get_associations: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let _ = self.service_roundtrip(conn, init.encode_to_vec()).await?;

        let up = ownership::Upstream {
            request: Some(ownership::Req {
                request_id: 2,
                deprecated_get_latest_manifests_req: Some(ownership::DeprecatedGetLatestManifestsReq {
                    deprecated_product_ids: product_ids.to_vec(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let raw = self.service_roundtrip(conn, up.encode_to_vec()).await?;
        let down = ownership::Downstream::decode(&raw[..])
            .context("decoding batch GetLatestManifests rsp")?;
        if let Some(rsp) = down.response.and_then(|r| r.deprecated_get_latest_manifests_rsp) {
            for m in rsp.manifests {
                if let Some(man) = m.manifest {
                    if !man.is_empty() {
                        out.insert(m.product_id, man);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Query the ownership service for the account's owned games.
    pub async fn owned_games(&mut self) -> Result<Vec<ownership::OwnedGame>> {
        let connection_id = self.open_connection("ownership_service").await?;

        let ownership_up = ownership::Upstream {
            request: Some(ownership::Req {
                request_id: 1,
                initialize_req: Some(ownership::InitializeReq {
                    get_associations: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let raw = self
            .service_roundtrip(connection_id, ownership_up.encode_to_vec())
            .await?;

        let down = ownership::Downstream::decode(&raw[..]).context("decoding ownership Downstream")?;
        let init = down
            .response
            .and_then(|r| r.initialize_rsp)
            .ok_or_else(|| anyhow!("no initialize_rsp from ownership_service"))?;
        if !init.success {
            bail!("ownership initialize returned success=false");
        }
        Ok(init.owned_games.map(|g| g.owned_games).unwrap_or_default())
    }
}
