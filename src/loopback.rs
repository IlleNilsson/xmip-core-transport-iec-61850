//! The IEC 61850 loopback: both ends on this machine, a client writing the
//! variable a one-association server holds.

use std::net::TcpListener;

use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{ArrivalIdentity, Taken, Transport};

use crate::Iec61850Transport;

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
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "Xmip reads the server's variable itself, so the server it read is in its origin",
        )
    }

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
