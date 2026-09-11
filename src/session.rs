//! The server's side of one association: what a test or the loopback puts
//! at the far end so a client can be driven without a relay in the room.
//!
//! Not an IED. One session serves one client and holds variables as byte
//! vectors keyed by domain and item: it answers initiate, serves a read
//! from a variable and a write into one, refuses what is not there with
//! the data access error a server would use, and ends at conclude.

use std::collections::HashMap;
use std::net::TcpListener;
use std::time::Duration;

use cotp::Connection;
use transport::error::{Result, protocol_error};

use crate::mms::{OBJECT_NON_EXISTENT, Pdu};

/// What the client asked, as [`Session::next_event`] reports it after
/// answering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Initiated,
    Read {
        domain: String,
        item: String,
        served: bool,
    },
    Written {
        domain: String,
        item: String,
        served: bool,
    },
}

pub struct Session {
    connection: Connection,
    variables: HashMap<(String, String), Vec<u8>>,
}

impl Session {
    /// Accept one client on `listener`, answering its CR. Initiate follows
    /// as the first event.
    ///
    /// # Errors
    /// Where the connection could not be accepted or did not open with CR.
    pub fn accept(listener: &TcpListener, timeout: Option<Duration>) -> Result<Self> {
        let connection = Connection::accept(listener, cotp::tpdu::DEFAULT_SIZE_CODE, timeout)?;
        Ok(Self {
            connection,
            variables: HashMap::new(),
        })
    }

    /// Hold `bytes` as `domain/item`.
    #[must_use]
    pub fn with_variable(mut self, domain: &str, item: &str, bytes: impl Into<Vec<u8>>) -> Self {
        self.variables
            .insert((domain.to_string(), item.to_string()), bytes.into());
        self
    }

    /// The bytes held as `domain/item`, as they are now.
    #[must_use]
    pub fn variable(&self, domain: &str, item: &str) -> Option<&[u8]> {
        self.variables
            .get(&(domain.to_string(), item.to_string()))
            .map(Vec::as_slice)
    }

    /// Where the client's requests come from, as the carrier writes it.
    #[must_use]
    pub fn origin(&self) -> String {
        self.connection.origin()
    }

    /// The client's address.
    #[must_use]
    pub fn peer(&self) -> std::net::SocketAddr {
        self.connection.peer()
    }

    /// Answer requests until the client concludes or disconnects.
    ///
    /// # Errors
    /// Where the connection broke or the client did not speak MMS.
    pub fn serve(&mut self) -> Result<()> {
        while self.next_event()?.is_some() {}
        Ok(())
    }

    /// Answer the next request and say what it was, or `None` when the
    /// client concluded or disconnected.
    ///
    /// # Errors
    /// Where the connection broke, or the client sent what is not a request.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        let Some(bytes) = self.connection.next_data()? else {
            return Ok(None);
        };
        let (answer, event) = match Pdu::decode(&bytes)? {
            Pdu::Initiate => (Pdu::InitiateOk, Some(Event::Initiated)),
            Pdu::Conclude => (Pdu::ConcludeOk, None),
            Pdu::Read {
                invoke,
                domain,
                item,
            } => self.read(invoke, domain, item),
            Pdu::Write {
                invoke,
                domain,
                item,
                data,
            } => self.write(invoke, domain, item, data),
            other => {
                return Err(protocol_error(format!(
                    "{other:?} is not a request this session serves"
                )));
            }
        };
        self.connection.send_data(&answer.encode())?;
        Ok(event)
    }

    fn read(&self, invoke: u32, domain: String, item: String) -> (Pdu, Option<Event>) {
        let answer = match self.variables.get(&(domain.clone(), item.clone())) {
            Some(data) => Pdu::ReadOk {
                invoke,
                data: data.clone(),
            },
            None => Pdu::ReadFailed {
                invoke,
                error: OBJECT_NON_EXISTENT,
            },
        };
        let served = matches!(answer, Pdu::ReadOk { .. });
        (
            answer,
            Some(Event::Read {
                domain,
                item,
                served,
            }),
        )
    }

    fn write(
        &mut self,
        invoke: u32,
        domain: String,
        item: String,
        data: Vec<u8>,
    ) -> (Pdu, Option<Event>) {
        let key = (domain.clone(), item.clone());
        let answer = match self.variables.get_mut(&key) {
            Some(held) => {
                *held = data;
                Pdu::WriteOk { invoke }
            }
            None => Pdu::WriteFailed {
                invoke,
                error: OBJECT_NON_EXISTENT,
            },
        };
        let served = matches!(answer, Pdu::WriteOk { .. });
        (
            answer,
            Some(Event::Written {
                domain,
                item,
                served,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;

    #[test]
    fn a_client_initiates_reads_writes_and_is_refused_what_is_not_there() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let client = std::thread::spawn(move || {
            let mut client = Client::connect(&address, Some(Duration::from_secs(2))).expect("c");
            assert_eq!(client.read("XMIP", "Stream").expect("read"), b"before");
            let long = vec![0x2a; 5000];
            client.write("XMIP", "Stream", &long).expect("write");
            assert_eq!(client.read("XMIP", "Stream").expect("back"), long);
            let missing = client.read("XMIP", "Nothing").expect_err("no");
            assert!(missing.message.contains("10"), "{missing}");
            assert!(client.write("XMIP", "Nothing", b"x").is_err());
            client.conclude().expect("conclude");
        });
        let mut session = Session::accept(&listener, Some(Duration::from_secs(2)))
            .expect("accept")
            .with_variable("XMIP", "Stream", b"before".to_vec());
        assert_eq!(
            session.next_event().expect("initiate"),
            Some(Event::Initiated)
        );
        assert!(session.origin().starts_with("cotp://127.0.0.1:"));
        assert!(session.peer().ip().is_loopback());
        session.serve().expect("serving");
        assert_eq!(
            session.variable("XMIP", "Stream").expect("held").len(),
            5000
        );
        client.join().expect("thread");
    }

    #[test]
    fn a_client_that_answers_instead_of_asking_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let client = std::thread::spawn(move || {
            let mut connection =
                Connection::connect(&address, &[1, 0], &[1, 2], 10, Some(Duration::from_secs(2)))
                    .expect("cc");
            connection
                .send_data(&Pdu::WriteOk { invoke: 1 }.encode())
                .expect("nonsense");
            std::thread::sleep(Duration::from_millis(200));
        });
        let mut session = Session::accept(&listener, Some(Duration::from_secs(2))).expect("accept");
        let error = session.next_event().expect_err("refused");
        assert!(!error.retryable, "{error}");
        client.join().expect("thread");
    }
}
