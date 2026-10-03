#![forbid(unsafe_code)]

//! Streams that are variables of an IEC 61850 server. One domain-specific
//! variable — a domain and an item — is one Stream: reading it is an MMS
//! read, writing it an MMS write, each an octet string of any length,
//! carried in ISO transport messages segmented to the TPDU size.
//!
//! IEC 61850 is the substation's standard: every protection relay, merging
//! unit and bay controller speaks it, MMS to the SCADA above on TCP port
//! 102 and GOOSE sideways to its neighbours on raw Ethernet. What is here
//! is the client-server side — the MMS PDUs this transport speaks
//! ([`mms`]) on the estate's X.690 reader (`xmip-core-library-asn1`,
//! shared with snmp), a client that initiates, reads,
//! writes and concludes, and [`Session`], one client's worth of server for
//! tests and the loopback — and the GOOSE frame with a Stream as its data
//! set ([`goose`]). Two carriers, as the manifest declares: MMS rides
//! `xmip-core-transport-cotp`, GOOSE `xmip-core-transport-ethernet`.
//!
//! Between COTP and MMS the standard stacks ISO session, presentation and
//! ACSE; this crate carries the MMS PDU directly in the COTP message and
//! says so. A relay that insists on the three layers needs them added
//! here, in the same place, before this transport reaches it; the estate's
//! two ends agree with each other today.
//!
//! **A receive is an MMS read, which consumes nothing at the server**, so
//! its verdict has nothing to tell it, whichever it is: a cycle that did not
//! complete loses nothing, and the next read finds the variable again.
//!
//! The origin URI names the server and the variable:
//! `iec61850://host:102/XMIP/Stream`. A target is the same, or a bare
//! `host:port` for the configured variable.

pub mod goose;
pub mod mms;
pub mod session;

use std::net::TcpListener;
use std::time::Duration;

use cotp::Connection;
pub use goose::Goose;
pub use mms::Pdu;
use net::Target;
pub use session::{Event, Session};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{Acknowledgement, Arrived, Configured, Directions, Pool, Pooled, Taken, Transport};
use xcore::settings::{Applies, Fixed, Kind, Presence, Read, Setting, Settings};

/// The TSAP a client presents, and the one a server listens on.
const CLIENT_TSAP: [u8; 2] = [0x00, 0x01];
const SERVER_TSAP: [u8; 2] = [0x00, 0x01];

/// The variable a Stream travels as unless a target says otherwise.
const STREAM_DOMAIN: &str = "XMIP";
const STREAM_ITEM: &str = "Stream";

/// One association with a server.
pub struct Client {
    connection: Connection,
    invoke: u32,
}

impl Client {
    /// Connect to the server at `address` and initiate.
    ///
    /// # Errors
    /// Where the server could not be reached, refused the TSAP, or did not
    /// answer initiate.
    pub fn connect(address: &str, timeout: Option<Duration>) -> Result<Self> {
        let connection = Connection::connect(
            address,
            &CLIENT_TSAP,
            &SERVER_TSAP,
            cotp::tpdu::DEFAULT_SIZE_CODE,
            timeout,
        )?;
        let mut client = Self {
            connection,
            invoke: 0,
        };
        match client.exchange(&Pdu::Initiate)? {
            Pdu::InitiateOk => Ok(client),
            other => Err(protocol_error(format!(
                "the server answered initiate with {other:?}"
            ))),
        }
    }

    /// The bytes of `domain/item`.
    ///
    /// # Errors
    /// A server that refuses the variable or goes away.
    pub fn read(&mut self, domain: &str, item: &str) -> Result<Vec<u8>> {
        let invoke = self.next_invoke();
        let request = Pdu::Read {
            invoke,
            domain: domain.into(),
            item: item.into(),
        };
        match self.confirmed(invoke, &request)? {
            Pdu::ReadOk { data, .. } => Ok(data),
            Pdu::ReadFailed { error, .. } => Err(refused(domain, item, error)),
            other => Err(protocol_error(format!(
                "the server answered read with {other:?}"
            ))),
        }
    }

    /// Write `bytes` to `domain/item`.
    ///
    /// # Errors
    /// A server that refuses the variable or goes away.
    pub fn write(&mut self, domain: &str, item: &str, bytes: &[u8]) -> Result<()> {
        let invoke = self.next_invoke();
        let request = Pdu::Write {
            invoke,
            domain: domain.into(),
            item: item.into(),
            data: bytes.to_vec(),
        };
        match self.confirmed(invoke, &request)? {
            Pdu::WriteOk { .. } => Ok(()),
            Pdu::WriteFailed { error, .. } => Err(refused(domain, item, error)),
            other => Err(protocol_error(format!(
                "the server answered write with {other:?}"
            ))),
        }
    }

    /// Conclude the association and disconnect.
    ///
    /// # Errors
    /// Where the server had already gone or did not answer conclude.
    pub fn conclude(mut self) -> Result<()> {
        match self.exchange(&Pdu::Conclude)? {
            Pdu::ConcludeOk => self.connection.disconnect(),
            other => Err(protocol_error(format!(
                "the server answered conclude with {other:?}"
            ))),
        }
    }

    const fn next_invoke(&mut self) -> u32 {
        self.invoke = self.invoke.wrapping_add(1);
        self.invoke
    }

    fn confirmed(&mut self, invoke: u32, request: &Pdu) -> Result<Pdu> {
        let answer = self.exchange(request)?;
        if answer.invoke() != Some(invoke) {
            return Err(protocol_error("an answer to another invoke"));
        }
        Ok(answer)
    }

    fn exchange(&mut self, request: &Pdu) -> Result<Pdu> {
        self.connection.send_data(&request.encode())?;
        let answer = self
            .connection
            .next_data()?
            .ok_or_else(|| protocol_error("the server closed before answering"))?;
        Pdu::decode(&answer)
    }
}

impl Pooled for Client {
    /// While the server has not closed the association's connection.
    fn usable(&mut self) -> bool {
        self.connection.usable()
    }
}

fn refused(domain: &str, item: &str, error: i64) -> transport::TransportError {
    protocol_error(format!(
        "{domain}/{item}: the server answered data access error {error}"
    ))
}

#[derive(Clone)]
pub struct Iec61850Transport {
    bind: String,
    domain: String,
    item: String,
    timeout: Option<Duration>,
    /// The associations a receive reads on and a send writes on,
    /// initiated once per server and kept.
    associations: Pool<Client>,
}

impl Iec61850Transport {
    /// Listen or connect at `bind`, about `XMIP/Stream`.
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            domain: STREAM_DOMAIN.into(),
            item: STREAM_ITEM.into(),
            timeout: None,
            associations: Pool::new(),
        }
    }

    /// Speak about `domain/item` instead.
    #[must_use]
    pub fn about(mut self, domain: &str, item: &str) -> Self {
        self.domain = domain.into();
        self.item = item.into();
        self
    }

    /// Give up on a peer that stops mid-message.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind through the carrier and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        cotp::CotpTransport::new(self.bind.clone()).bind()
    }

    /// Accept one client on an already-bound listener.
    ///
    /// # Errors
    /// Where the connection could not be accepted or did not open with CR.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        Session::accept(listener, self.timeout)
    }

    /// Connect to `address` and initiate.
    ///
    /// # Errors
    /// As [`Client::connect`].
    pub fn connect(&self, address: &str) -> Result<Client> {
        Client::connect(address, self.timeout)
    }

    /// `iec61850://host:102/<domain>/<item>` in full, or `host:port` for
    /// the configured variable.
    fn resolve(&self, target: &str) -> Result<(String, String, String)> {
        let Some((authority, path)) =
            Target::under(&["iec61850"], target).map(|named| (named.authority(), named.path()))
        else {
            return Ok((target.to_string(), self.domain.clone(), self.item.clone()));
        };
        if path.is_empty() {
            return Ok((
                authority.to_string(),
                self.domain.clone(),
                self.item.clone(),
            ));
        }
        let (domain, item) = path
            .split_once('/')
            .filter(|(domain, item)| !domain.is_empty() && !item.is_empty())
            .ok_or_else(|| protocol_error(format!("{target:?} does not name <domain>/<item>")))?;
        Ok((authority.to_string(), domain.to_string(), item.to_string()))
    }
}

impl Transport for Iec61850Transport {
    fn name(&self) -> &'static str {
        "iec-61850"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a poll reads again what is not yet told")
    }

    /// One read of the variable, on the association kept for the server
    /// and initiated on the first receive: its bytes as one Stream, whole.
    /// The verdict has nothing to tell the server, whichever it is: an MMS
    /// read consumes nothing, so a cycle that did not complete loses
    /// nothing — the next read finds the variable again.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let bytes = self.associations.exchange(
            self.bind.as_str(),
            || self.connect(&self.bind),
            |client| client.read(&self.domain, &self.item),
        )?;
        Ok(vec![Arrived::whole(
            format!("iec61850://{}/{}/{}", self.bind, self.domain, self.item),
            bytes,
            Acknowledgement::unconsumed(),
        )])
    }

    /// One write of `bytes` to the variable `target` names, on the
    /// association kept for its server and initiated on the first send.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (address, domain, item) = self.resolve(target)?;
        self.associations.exchange(
            address.as_str(),
            || self.connect(&address),
            |client| client.write(&domain, &item, bytes),
        )
    }
}

impl Configured for Iec61850Transport {
    /// The address is the server's host and port, 102 by the standard:
    /// where a Location connects.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "domain",
                kind: Kind::Text,
                presence: Presence::Default(Fixed::Text(STREAM_DOMAIN)),
                meaning: "The domain of the variable that is the Stream.",
                applies: Applies::Both,
            },
            Setting {
                name: "item",
                kind: Kind::Text,
                presence: Presence::Default(Fixed::Text(STREAM_ITEM)),
                meaning: "The item of the variable that is the Stream, within its domain.",
                applies: Applies::Both,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a peer that stops mid-message is waited on; unbounded when \
                          left out.",
                applies: Applies::Both,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let transport = Self::new(address).about(settings.text("domain"), settings.text("item"));
        Ok(match settings.optional_duration("timeout") {
            Some(timeout) => transport.timing_out_after(timeout),
            None => transport,
        })
    }
}

impl Iec61850Transport {
    /// Both ends on this machine: an ephemeral local port, the loopback
    /// timeout on either side of the association.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for Iec61850Transport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        let (domain, item) = (&self.domain, &self.item);
        let mut session = self
            .accept_one(listener)?
            .with_variable(domain, item, Vec::new());
        session.serve()?;
        let bytes = session
            .variable(domain, item)
            .ok_or_else(|| protocol_error("the variable went missing"))?
            .to_vec();
        Ok(Taken::new(
            format!("iec61850://{}/{domain}/{item}", session.peer()),
            bytes,
        ))
    }
}

/// An octet string has no bound in BER and the carrier segments the PDU
/// to its TPDU size: no ceiling is a fact of the protocol.
impl Loopback for Iec61850Transport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::new("127.0.0.1:0")
            .about(&self.domain, &self.item)
            .timing_out_after(self.timeout.unwrap_or(LOOPBACK_TIMEOUT))
            .send(address, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iec_61850_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(Iec61850Transport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("domain".to_string(), Given::Text("BAY1".to_string())),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let built = Iec61850Transport::open("relay:102", Applies::Receive, &given).expect("built");
        assert_eq!(built.domain, "BAY1");
        assert_eq!(built.item, STREAM_ITEM);
        assert_eq!(built.timeout, Some(Duration::from_secs(2)));
        let given = [("domain".to_string(), Given::Integer(1))];
        let Err(refused) = Iec61850Transport::open("relay:102", Applies::Send, &given) else {
            panic!("a domain is text");
        };
        assert!(
            refused.message.contains("\"domain\""),
            "{}",
            refused.message
        );
    }
    use transport::payload::edge_payloads;

    #[test]
    fn a_loopback_round_writes_a_variable_on_an_association() {
        let loopback = Iec61850Transport::loopback();
        let arrived = loopback.round(b"an octet string").expect("round");
        assert_eq!(arrived.bytes, b"an octet string");
        assert!(arrived.origin_uri.starts_with("iec61850://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/XMIP/Stream"));
        let long = vec![0x2a; 20_000];
        assert_eq!(loopback.round(&long).expect("segmented").bytes, long);
        assert!(loopback.ceiling().is_none());
        assert!(loopback.refuses(&long).is_none());
        assert_eq!(loopback.name(), "iec-61850");
        assert!(loopback.claims().is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole() {
        let loopback = Iec61850Transport::loopback();
        for (name, bytes) in edge_payloads() {
            let arrived = loopback
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
    }

    #[test]
    fn a_location_reads_and_writes_a_variable_the_target_names() {
        let server = Iec61850Transport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(2));
        let (listener, address) = server.bind().expect("bind");
        let serving = std::thread::spawn(move || {
            // One server, so one association reads and writes.
            let mut first = server
                .accept_one(&listener)
                .expect("accept")
                .with_variable("XMIP", "Stream", b"held".to_vec())
                .with_variable("Relay", "Setting", vec![0]);
            first.serve().expect("serve");
            first.variable("Relay", "Setting").map(<[u8]>::to_vec)
        });
        let near = Iec61850Transport::new(&address).timing_out_after(Duration::from_secs(2));
        let arrived = near.receive().expect("read").remove(0);
        assert!(arrived.defers(), "a read consumes nothing: nothing to lose");
        let arrived = arrived.taken().expect("taken");
        assert_eq!(arrived.bytes, b"held");
        assert_eq!(
            arrived.origin_uri,
            format!("iec61850://{address}/XMIP/Stream")
        );
        // A refused cycle loses nothing: the next read finds it again.
        near.receive()
            .expect("read")
            .remove(0)
            .failed()
            .expect("refused");
        let again = near.receive().expect("again").remove(0);
        assert_eq!(again.taken().expect("taken").bytes, b"held");
        near.send(&format!("iec61850://{address}/Relay/Setting"), &[7, 7])
            .expect("write");
        assert_eq!(near.associations.opened(), 1);
        // Its kept association closes with it, which ends the serving.
        drop(near);
        let near = Iec61850Transport::new(&address);
        assert_eq!(serving.join().expect("thread"), Some(vec![7, 7]));
        assert_eq!(near.resolve("plc:102").expect("bare").1, "XMIP");
        assert!(near.resolve("iec61850://plc:102/only").is_err());
        assert!(near.resolve("iec61850://plc:102//item").is_err());
    }

    #[test]
    fn a_thousand_reads_initiate_once_and_an_association_the_server_closed_is_replaced() {
        const RECEIVES: usize = 1000;
        let server = Iec61850Transport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(5));
        let (listener, address) = server.bind().expect("bind");
        let near = Iec61850Transport::new(&address).timing_out_after(Duration::from_secs(5));
        let reading = near.clone();
        let reader = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            for _ in 0..RECEIVES {
                assert_eq!(reading.receive()?.remove(0).taken()?.bytes, b"held");
            }
            let took = began.elapsed();
            // Generous for a debug build under load: a millisecond a read.
            assert!(took < Duration::from_millis(RECEIVES as u64), "{took:?}");
            reading.receive()?.remove(0).taken()
        });
        let serve = |session: &mut Session, reads: usize| {
            let (mut initiated, mut read) = (0, 0);
            while read < reads {
                match session.next_event().expect("serving").expect("one") {
                    Event::Initiated => initiated += 1,
                    Event::Read { served: true, .. } => read += 1,
                    other => panic!("{other:?}"),
                }
            }
            initiated
        };
        let accept = || {
            server
                .accept_one(&listener)
                .expect("an association")
                .with_variable("XMIP", "Stream", b"held".to_vec())
        };
        // One connect and initiate for every read.
        let mut session = accept();
        assert_eq!(serve(&mut session, RECEIVES), 1);
        drop(session);
        let mut again = accept();
        serve(&mut again, 1);
        assert_eq!(reader.join().expect("thread").expect("read").bytes, b"held");
        assert_eq!(near.associations.opened(), 2);
    }

    #[test]
    fn a_far_end_that_does_not_speak_mms_is_a_permanent_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let far_end = std::thread::spawn(move || {
            let mut connection =
                Connection::accept(&listener, 10, Some(Duration::from_secs(2))).expect("cc");
            let initiate = connection.next_data().expect("initiate").expect("one");
            assert_eq!(initiate[0], 0xa8);
            connection
                .send_data(b"<34>1 - - - - - - not MMS")
                .expect("nonsense");
            std::thread::sleep(Duration::from_millis(200));
        });
        let error = Iec61850Transport::new(&address)
            .timing_out_after(Duration::from_secs(2))
            .receive()
            .expect_err("refused");
        assert!(!error.retryable, "{error}");
        far_end.join().expect("thread");
    }
}
