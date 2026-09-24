//! The manufacturing message specification, ISO 9506-2, as IEC 61850-8-1
//! maps a client-server exchange onto it: initiate, a write and a read of
//! one domain-specific variable holding an octet string, and conclude.
//!
//! Every PDU is one BER element whose context tag says which: `[8]` and
//! `[9]` initiate, `[0]` a confirmed request and `[1]` its response — an
//! invoke identifier and then the service, `[4]` read or `[5]` write —
//! `[11]` and `[12]` conclude. A variable is named by domain and item; the
//! data is `Data`'s octet-string choice, `[9]`.

use asn1::{INTEGER, NULL, SEQUENCE, VISIBLE_STRING, context};
use transport::error::{Result, protocol_error};

/// The MMS version this crate proposes and accepts.
pub const VERSION: i64 = 1;
/// The largest PDU this crate proposes: what the estate's COTP carries in
/// one TPKT frame.
pub const MAX_PDU: i64 = 65_000;

/// The data access error an IED answers for a variable it does not have.
pub const OBJECT_NON_EXISTENT: i64 = 10;

/// One PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pdu {
    Initiate,
    InitiateOk,
    Write {
        invoke: u32,
        domain: String,
        item: String,
        data: Vec<u8>,
    },
    WriteOk {
        invoke: u32,
    },
    WriteFailed {
        invoke: u32,
        error: i64,
    },
    Read {
        invoke: u32,
        domain: String,
        item: String,
    },
    ReadOk {
        invoke: u32,
        data: Vec<u8>,
    },
    ReadFailed {
        invoke: u32,
        error: i64,
    },
    Conclude,
    ConcludeOk,
}

const INITIATE_REQUEST: u8 = context(8, true);
const INITIATE_RESPONSE: u8 = context(9, true);
const CONFIRMED_REQUEST: u8 = context(0, true);
const CONFIRMED_RESPONSE: u8 = context(1, true);
const CONCLUDE_REQUEST: u8 = context(11, false);
const CONCLUDE_RESPONSE: u8 = context(12, false);
const READ: u8 = context(4, true);
const WRITE: u8 = context(5, true);
const OCTET_STRING_DATA: u8 = context(9, false);

impl Pdu {
    /// The PDU as bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Initiate => asn1::tlv(INITIATE_REQUEST, &initiate_detail()),
            Self::InitiateOk => asn1::tlv(INITIATE_RESPONSE, &initiate_detail()),
            Self::Write {
                invoke,
                domain,
                item,
                data,
            } => {
                let list_of_data = asn1::tlv(context(0, true), &asn1::tlv(OCTET_STRING_DATA, data));
                let body = [variables(domain, item), list_of_data].concat();
                confirmed(CONFIRMED_REQUEST, *invoke, WRITE, &body)
            }
            Self::WriteOk { invoke } => confirmed(
                CONFIRMED_RESPONSE,
                *invoke,
                WRITE,
                &asn1::tlv(context(1, false), &[]),
            ),
            Self::WriteFailed { invoke, error } => confirmed(
                CONFIRMED_RESPONSE,
                *invoke,
                WRITE,
                &asn1::tlv(context(0, false), &asn1::integer(*error)),
            ),
            Self::Read {
                invoke,
                domain,
                item,
            } => {
                let specification = asn1::tlv(context(1, true), &variables(domain, item));
                confirmed(CONFIRMED_REQUEST, *invoke, READ, &specification)
            }
            Self::ReadOk { invoke, data } => {
                let results = asn1::tlv(context(1, true), &asn1::tlv(OCTET_STRING_DATA, data));
                confirmed(CONFIRMED_RESPONSE, *invoke, READ, &results)
            }
            Self::ReadFailed { invoke, error } => {
                let failure = asn1::tlv(context(0, false), &asn1::integer(*error));
                let results = asn1::tlv(context(1, true), &failure);
                confirmed(CONFIRMED_RESPONSE, *invoke, READ, &results)
            }
            Self::Conclude => asn1::tlv(CONCLUDE_REQUEST, &[]),
            Self::ConcludeOk => asn1::tlv(CONCLUDE_RESPONSE, &[]),
        }
    }

    /// The PDU `bytes` carry.
    ///
    /// # Errors
    /// Not one of the PDUs this crate speaks, or one whose shape is not as
    /// the specification lays it out.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (tag, contents, rest) = asn1::read(bytes)?;
        if !rest.is_empty() {
            return Err(protocol_error("bytes after the PDU"));
        }
        match tag {
            INITIATE_REQUEST => Ok(Self::Initiate),
            INITIATE_RESPONSE => Ok(Self::InitiateOk),
            CONCLUDE_REQUEST => Ok(Self::Conclude),
            CONCLUDE_RESPONSE => Ok(Self::ConcludeOk),
            CONFIRMED_REQUEST | CONFIRMED_RESPONSE => {
                let (invoke, service, body) = split_confirmed(contents)?;
                match (tag, service) {
                    (CONFIRMED_REQUEST, WRITE) => decode_write(invoke, body),
                    (CONFIRMED_REQUEST, READ) => decode_read(invoke, body),
                    (CONFIRMED_RESPONSE, WRITE) => decode_write_result(invoke, body),
                    (CONFIRMED_RESPONSE, READ) => decode_read_result(invoke, body),
                    (_, other) => Err(protocol_error(format!(
                        "service {other:#04x} is not one this transport speaks"
                    ))),
                }
            }
            other => Err(protocol_error(format!(
                "PDU {other:#04x} is not MMS this transport speaks"
            ))),
        }
    }

    /// The invoke identifier a confirmed PDU carries, or `None`.
    #[must_use]
    pub const fn invoke(&self) -> Option<u32> {
        match self {
            Self::Write { invoke, .. }
            | Self::WriteOk { invoke }
            | Self::WriteFailed { invoke, .. }
            | Self::Read { invoke, .. }
            | Self::ReadOk { invoke, .. }
            | Self::ReadFailed { invoke, .. } => Some(*invoke),
            _ => None,
        }
    }
}

/// The initiate detail both sides state: one outstanding service each way,
/// no nesting, version 1, no parameter CBB, no services listed.
fn initiate_detail() -> Vec<u8> {
    let detail = [
        asn1::tlv(context(0, false), &asn1::integer(VERSION)),
        asn1::tlv(context(1, false), &[0x05, 0xf1, 0x00]),
        asn1::tlv(
            context(2, false),
            &[0x03, 0xee, 0x18, 0x00, 0x00, 0x00, 0x00],
        ),
    ]
    .concat();
    [
        asn1::tlv(context(0, false), &asn1::integer(MAX_PDU)),
        asn1::tlv(context(1, false), &asn1::integer(1)),
        asn1::tlv(context(2, false), &asn1::integer(1)),
        asn1::tlv(context(3, false), &asn1::integer(0)),
        asn1::tlv(context(4, true), &detail),
    ]
    .concat()
}

fn confirmed(tag: u8, invoke: u32, service: u8, body: &[u8]) -> Vec<u8> {
    let contents = [
        asn1::tlv(INTEGER, &asn1::integer(i64::from(invoke))),
        asn1::tlv(service, body),
    ]
    .concat();
    asn1::tlv(tag, &contents)
}

/// `listOfVariable [0]` of one domain-specific name.
fn variables(domain: &str, item: &str) -> Vec<u8> {
    let name = [
        asn1::tlv(VISIBLE_STRING, domain.as_bytes()),
        asn1::tlv(VISIBLE_STRING, item.as_bytes()),
    ]
    .concat();
    let object_name = asn1::tlv(context(0, true), &asn1::tlv(context(1, true), &name));
    asn1::tlv(context(0, true), &asn1::tlv(SEQUENCE, &object_name))
}

fn split_confirmed(contents: &[u8]) -> Result<(u32, u8, &[u8])> {
    let (tag, invoke, rest) = asn1::read(contents)?;
    if tag != INTEGER {
        return Err(protocol_error(
            "a confirmed PDU without its invoke identifier",
        ));
    }
    let invoke = u32::try_from(asn1::read_integer(invoke)?)
        .map_err(|_| protocol_error("an invoke identifier outside thirty-two bits"))?;
    let (service, body, rest) = asn1::read(rest)?;
    if !rest.is_empty() {
        return Err(protocol_error("bytes after the service"));
    }
    Ok((invoke, service, body))
}

/// The domain and item of a `listOfVariable [0]`.
fn read_name(list: &[u8]) -> Result<(String, String)> {
    let (_, sequence, _) = asn1::read(list)?;
    let (_, object_name, _) = asn1::read(sequence)?;
    let (tag, domain_specific, _) = asn1::read(object_name)?;
    if tag != context(1, true) {
        return Err(protocol_error("a name that is not domain-specific"));
    }
    let parts = asn1::read_all(domain_specific)?;
    match parts.as_slice() {
        [(VISIBLE_STRING, domain), (VISIBLE_STRING, item)] => Ok((
            String::from_utf8_lossy(domain).into_owned(),
            String::from_utf8_lossy(item).into_owned(),
        )),
        _ => Err(protocol_error(
            "a domain-specific name without its two identifiers",
        )),
    }
}

fn read_octet_string(list: &[u8]) -> Result<Vec<u8>> {
    let (tag, data, _) = asn1::read(list)?;
    if tag != OCTET_STRING_DATA {
        return Err(protocol_error("data that is not an octet string"));
    }
    Ok(data.to_vec())
}

fn decode_write(invoke: u32, body: &[u8]) -> Result<Pdu> {
    let (_, list_of_variable, rest) = asn1::read(body)?;
    let (_, list_of_data, _) = asn1::read(rest)?;
    let (domain, item) = read_name(list_of_variable)?;
    Ok(Pdu::Write {
        invoke,
        domain,
        item,
        data: read_octet_string(list_of_data)?,
    })
}

fn decode_read(invoke: u32, body: &[u8]) -> Result<Pdu> {
    let elements = asn1::read_all(body)?;
    let specification = asn1::find(&elements, context(1, true))?;
    let (_, list_of_variable, _) = asn1::read(specification)?;
    let (domain, item) = read_name(list_of_variable)?;
    Ok(Pdu::Read {
        invoke,
        domain,
        item,
    })
}

fn decode_write_result(invoke: u32, body: &[u8]) -> Result<Pdu> {
    let (tag, contents, _) = asn1::read(body)?;
    match tag {
        t if t == context(1, false) || t == NULL => Ok(Pdu::WriteOk { invoke }),
        t if t == context(0, false) => Ok(Pdu::WriteFailed {
            invoke,
            error: asn1::read_integer(contents)?,
        }),
        _ => Err(protocol_error(
            "a write result that is neither success nor failure",
        )),
    }
}

fn decode_read_result(invoke: u32, body: &[u8]) -> Result<Pdu> {
    let (_, results, _) = asn1::read(body)?;
    let (tag, contents, _) = asn1::read(results)?;
    match tag {
        OCTET_STRING_DATA => Ok(Pdu::ReadOk {
            invoke,
            data: contents.to_vec(),
        }),
        t if t == context(0, false) => Ok(Pdu::ReadFailed {
            invoke,
            error: asn1::read_integer(contents)?,
        }),
        _ => Err(protocol_error(
            "an access result that is neither data nor failure",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pdu_round_trips() {
        let pdus = [
            Pdu::Initiate,
            Pdu::InitiateOk,
            Pdu::Write {
                invoke: 7,
                domain: "XMIP".into(),
                item: "Stream".into(),
                data: vec![1, 2, 3],
            },
            Pdu::WriteOk { invoke: 7 },
            Pdu::WriteFailed {
                invoke: 8,
                error: OBJECT_NON_EXISTENT,
            },
            Pdu::Read {
                invoke: 9,
                domain: "XMIP".into(),
                item: "Stream".into(),
            },
            Pdu::ReadOk {
                invoke: 9,
                data: vec![0; 300],
            },
            Pdu::ReadFailed {
                invoke: 10,
                error: OBJECT_NON_EXISTENT,
            },
            Pdu::Conclude,
            Pdu::ConcludeOk,
        ];
        for pdu in pdus {
            assert_eq!(Pdu::decode(&pdu.encode()).expect("decode"), pdu, "{pdu:?}");
        }
        assert_eq!(Pdu::Conclude.encode(), [0x8b, 0x00]);
        assert_eq!(Pdu::WriteOk { invoke: 1 }.invoke(), Some(1));
        assert!(Pdu::Initiate.invoke().is_none());
    }

    #[test]
    fn a_write_is_laid_out_as_the_specification_says() {
        let write = Pdu::Write {
            invoke: 1,
            domain: "D".into(),
            item: "I".into(),
            data: b"x".to_vec(),
        }
        .encode();
        assert_eq!(write[0], 0xa0, "confirmed-RequestPDU");
        assert_eq!(&write[2..5], &[0x02, 0x01, 0x01], "invokeID 1");
        assert_eq!(write[5], 0xa5, "write");
        assert_eq!(write[7], 0xa0, "listOfVariable");
        assert_eq!(write[9], 0x30, "SEQUENCE");
        assert_eq!(write[11], 0xa0, "name");
        assert_eq!(write[13], 0xa1, "domain-specific");
        assert_eq!(&write[15..18], &[0x1a, 0x01, b'D']);
        assert_eq!(&write[18..21], &[0x1a, 0x01, b'I']);
        assert_eq!(write[21], 0xa0, "listOfData");
        assert_eq!(&write[23..26], &[0x89, 0x01, b'x'], "octet-string");
    }

    #[test]
    fn what_is_not_mms_this_transport_speaks_is_refused() {
        assert!(Pdu::decode(&[]).is_err(), "empty");
        assert!(Pdu::decode(&[0xa2, 0x00]).is_err(), "unconfirmed-PDU");
        assert!(Pdu::decode(&[0x8b, 0x00, 0x00]).is_err(), "bytes after");
        assert!(Pdu::decode(&[0xa0, 0x02, 0x05, 0x00]).is_err(), "no invoke");
        assert!(
            Pdu::decode(&[0xa0, 0x05, 0x02, 0x01, 0x01, 0xa6, 0x00]).is_err(),
            "service 6"
        );
        assert!(
            Pdu::decode(&[0xa0, 0x03, 0x02, 0x01, 0x01]).is_err(),
            "no service"
        );
        let vmd = Pdu::Read {
            invoke: 1,
            domain: "D".into(),
            item: "I".into(),
        };
        let mut bytes = vmd.encode();
        bytes[15] = 0xa0;
        assert!(Pdu::decode(&bytes).is_err(), "a vmd-specific name");
        assert!(
            Pdu::decode(&[0xa1, 0x05, 0x02, 0x01, 0x01, 0xa5, 0x00]).is_err(),
            "empty write result"
        );
    }
}
