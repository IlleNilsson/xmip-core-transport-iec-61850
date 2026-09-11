//! GOOSE, IEC 61850-8-1 clause 18: the generic object oriented substation
//! event, one publisher's state multicast on raw Ethernet to every
//! subscriber on the bay, repeated with a rising sequence number until the
//! state changes and the state number rises instead.
//!
//! The frame is `EtherType` `0x88b8`, an application identifier, a length,
//! two reserved words, and the goosePDU — `[APPLICATION 1]` — whose eleven
//! context-tagged fields name the control block, the data set, the time,
//! the two numbers, and then `allData`: here, octet strings.

use ethernet::{Frame, Mac};
use transport::error::{Result, protocol_error};

use crate::ber::{self, context};

/// The `EtherType` of every GOOSE frame.
pub const ETHERTYPE: u16 = 0x88b8;

/// The first of the multicast addresses IEC 61850-8-1 reserves for GOOSE.
pub const MULTICAST: Mac = Mac([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00]);

const GOOSE_PDU: u8 = 0x61;
const OCTET_STRING_DATA: u8 = context(9, false);

/// One GOOSE message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Goose {
    pub app_id: u16,
    pub gocb_ref: String,
    pub time_allowed_to_live: u32,
    pub dat_set: String,
    pub go_id: String,
    /// The UTC time as the eight bytes IEC 61850 lays them out.
    pub time: [u8; 8],
    pub st_num: u32,
    pub sq_num: u32,
    pub simulation: bool,
    pub conf_rev: u32,
    pub nds_com: bool,
    /// The data set's entries, every one an octet string.
    pub data: Vec<Vec<u8>>,
}

impl Goose {
    /// The frame's payload: application identifier, length, reserved words,
    /// the PDU.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let all_data: Vec<u8> = self
            .data
            .iter()
            .flat_map(|entry| ber::tlv(OCTET_STRING_DATA, entry))
            .collect();
        let entries = i64::try_from(self.data.len()).unwrap_or(i64::MAX);
        let fields = [
            ber::tlv(context(0, false), self.gocb_ref.as_bytes()),
            ber::tlv(
                context(1, false),
                &ber::integer(i64::from(self.time_allowed_to_live)),
            ),
            ber::tlv(context(2, false), self.dat_set.as_bytes()),
            ber::tlv(context(3, false), self.go_id.as_bytes()),
            ber::tlv(context(4, false), &self.time),
            ber::tlv(context(5, false), &ber::integer(i64::from(self.st_num))),
            ber::tlv(context(6, false), &ber::integer(i64::from(self.sq_num))),
            ber::tlv(context(7, false), &[u8::from(self.simulation) * 0xff]),
            ber::tlv(context(8, false), &ber::integer(i64::from(self.conf_rev))),
            ber::tlv(context(9, false), &[u8::from(self.nds_com) * 0xff]),
            ber::tlv(context(10, false), &ber::integer(entries)),
            ber::tlv(context(11, true), &all_data),
        ]
        .concat();
        let pdu = ber::tlv(GOOSE_PDU, &fields);
        let mut out = Vec::with_capacity(8 + pdu.len());
        out.extend_from_slice(&self.app_id.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(8 + pdu.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&pdu);
        out
    }

    /// The message `payload` carries.
    ///
    /// # Errors
    /// Shorter than its header, a length that is not the payload's, a PDU
    /// that is not a goosePDU, a field missing, or data that is not octet
    /// strings.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let head = payload
            .get(..8)
            .ok_or_else(|| protocol_error("shorter than a GOOSE header"))?;
        let length = usize::from(u16::from_be_bytes([head[2], head[3]]));
        if length != payload.len() {
            return Err(protocol_error("a GOOSE length that is not the payload's"));
        }
        let (tag, fields, _) = ber::read(&payload[8..])?;
        if tag != GOOSE_PDU {
            return Err(protocol_error("a PDU that is not a goosePDU"));
        }
        let fields = ber::read_all(fields)?;
        let field = |n: u8| ber::find(&fields, context(n, false));
        let number = |n: u8| -> Result<u32> {
            u32::try_from(ber::read_integer(field(n)?)?)
                .map_err(|_| protocol_error("a GOOSE number outside thirty-two bits"))
        };
        let string =
            |n: u8| -> Result<String> { Ok(String::from_utf8_lossy(field(n)?).into_owned()) };
        let flag = |n: u8| -> Result<bool> { Ok(field(n)?.first().is_some_and(|&b| b != 0)) };
        let mut time = [0u8; 8];
        let stamp = field(4)?;
        if stamp.len() != 8 {
            return Err(protocol_error("a time that is not eight bytes"));
        }
        time.copy_from_slice(stamp);
        let mut data = Vec::new();
        for (tag, entry) in ber::read_all(ber::find(&fields, context(11, true))?)? {
            if tag != OCTET_STRING_DATA {
                return Err(protocol_error(
                    "a data set entry that is not an octet string",
                ));
            }
            data.push(entry.to_vec());
        }
        if number(10)? != u32::try_from(data.len()).unwrap_or(u32::MAX) {
            return Err(protocol_error("numDatSetEntries that is not the entries"));
        }
        Ok(Self {
            app_id: u16::from_be_bytes([head[0], head[1]]),
            gocb_ref: string(0)?,
            time_allowed_to_live: number(1)?,
            dat_set: string(2)?,
            go_id: string(3)?,
            time,
            st_num: number(5)?,
            sq_num: number(6)?,
            simulation: flag(7)?,
            conf_rev: number(8)?,
            nds_com: flag(9)?,
            data,
        })
    }

    /// The message as a frame from `source` to the GOOSE multicast.
    ///
    /// # Errors
    /// A message over what one frame carries.
    pub fn frame(&self, source: Mac) -> Result<Frame> {
        Frame::new(MULTICAST, source, ETHERTYPE, &self.encode())
    }

    /// The message a frame carries, or `None` where the frame is not GOOSE.
    ///
    /// # Errors
    /// As [`Goose::decode`].
    pub fn from_frame(frame: &Frame) -> Result<Option<Self>> {
        if frame.ethertype != ETHERTYPE {
            return Ok(None);
        }
        Self::decode(&frame.payload).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethernet::Link;
    use std::sync::Arc;

    fn sample() -> Goose {
        Goose {
            app_id: 0x0001,
            gocb_ref: "IED1CFG/LLN0$GO$gcb01".into(),
            time_allowed_to_live: 2000,
            dat_set: "IED1CFG/LLN0$DS1".into(),
            go_id: "IED1_gcb01".into(),
            time: [0x5f, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x0a],
            st_num: 3,
            sq_num: 17,
            simulation: false,
            conf_rev: 1,
            nds_com: false,
            data: vec![b"trip".to_vec(), vec![0xff; 40]],
        }
    }

    #[test]
    fn a_goose_frame_goes_over_the_ethernet_loopback_and_back() {
        let link: Arc<dyn Link> = Arc::new(ethernet::Loopback::new());
        let goose = sample();
        let frame = goose.frame(Mac([2, 0, 0, 0, 0, 1])).expect("frame");
        assert_eq!(frame.destination, MULTICAST);
        assert_eq!(frame.ethertype, ETHERTYPE);
        assert_eq!(
            &frame.payload[..4],
            &[0, 1, 0, u8::try_from(frame.payload.len()).expect("short")]
        );
        assert_eq!(frame.payload[8], 0x61, "goosePDU");
        link.transmit(&frame).expect("transmit");
        let back = link
            .receive(std::time::Duration::ZERO)
            .expect("receive")
            .expect("frame");
        assert_eq!(Goose::from_frame(&back).expect("goose"), Some(goose));
        let ip = Frame::new(MULTICAST, Mac([2; 6]), 0x0800, &[0x45]).expect("ip");
        assert_eq!(Goose::from_frame(&ip).expect("not goose"), None);
    }

    #[test]
    fn what_is_not_goose_is_refused() {
        assert!(Goose::decode(&[0, 1, 0]).is_err(), "short");
        let mut wire = sample().encode();
        wire[3] ^= 1;
        assert!(Goose::decode(&wire).is_err(), "length");
        let mut wire = sample().encode();
        wire[8] = 0x30;
        assert!(Goose::decode(&wire).is_err(), "not a goosePDU");
        let mut no_count = sample();
        no_count.data.clear();
        let mut wire = no_count.encode();
        let at = wire.len() - 4;
        wire[at] = 0x89;
        assert!(Goose::decode(&wire).is_err(), "a stray entry");
        let mut goose = sample();
        goose.simulation = true;
        goose.nds_com = true;
        let wire = goose.encode();
        assert!(wire.windows(3).any(|w| w == [context(7, false), 1, 0xff]));
        assert_eq!(Goose::decode(&wire).expect("flags"), goose);
        assert_eq!(ber::BOOLEAN, 0x01, "the tag a bare BOOLEAN would carry");
    }
}
