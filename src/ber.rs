//! The basic encoding rules, as much of ISO 8825-1 as MMS and GOOSE use:
//! a one-byte tag, a length in short or long form, the contents. Nothing
//! here knows what a tag means.

use transport::error::{Result, protocol_error};

/// A context-specific tag: `[n]`, constructed or primitive.
#[must_use]
pub const fn context(n: u8, constructed: bool) -> u8 {
    0x80 | if constructed { 0x20 } else { 0x00 } | (n & 0x1f)
}

/// The universal tags this crate writes.
pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const VISIBLE_STRING: u8 = 0x1a;
pub const SEQUENCE: u8 = 0x30;

/// One tag, length and contents.
#[must_use]
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + contents.len());
    out.push(tag);
    let length = contents.len();
    if length < 0x80 {
        out.push(u8::try_from(length).unwrap_or(0));
    } else {
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | u8::try_from(bytes.len() - first).unwrap_or(0));
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(contents);
    out
}

/// An INTEGER's contents: the shortest two's complement.
#[must_use]
pub fn integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut first = 0;
    while first < 7 {
        let sign_extends = (bytes[first] == 0x00 && bytes[first + 1] & 0x80 == 0)
            || (bytes[first] == 0xff && bytes[first + 1] & 0x80 != 0);
        if !sign_extends {
            break;
        }
        first += 1;
    }
    bytes[first..].to_vec()
}

/// The value an INTEGER's contents carry.
///
/// # Errors
/// Empty, or wider than sixty-four bits.
pub fn read_integer(contents: &[u8]) -> Result<i64> {
    if contents.is_empty() || contents.len() > 8 {
        return Err(protocol_error("an INTEGER of no bytes or too many"));
    }
    let mut value: i64 = if contents[0] & 0x80 != 0 { -1 } else { 0 };
    for &byte in contents {
        value = (value << 8) | i64::from(byte);
    }
    Ok(value)
}

/// The first element of `bytes`: its tag, its contents, and what follows.
///
/// # Errors
/// Cut short, a tag of the multi-byte form, or a length past the end.
pub fn read(bytes: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes
        .split_first()
        .ok_or_else(|| protocol_error("an element cut short at its tag"))?;
    if tag & 0x1f == 0x1f {
        return Err(protocol_error("a tag of the multi-byte form"));
    }
    let (&first, rest) = rest
        .split_first()
        .ok_or_else(|| protocol_error("an element cut short at its length"))?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err(protocol_error(
                "a length of the indefinite form, or too wide",
            ));
        }
        let (digits, rest) = rest
            .split_at_checked(count)
            .ok_or_else(|| protocol_error("an element cut short in its length"))?;
        let length = digits
            .iter()
            .fold(0usize, |acc, &d| (acc << 8) | usize::from(d));
        (length, rest)
    };
    let (contents, rest) = rest
        .split_at_checked(length)
        .ok_or_else(|| protocol_error("a length past the end"))?;
    Ok((tag, contents, rest))
}

/// Every element of `bytes`, in order, as tag and contents.
///
/// # Errors
/// As [`read`].
pub fn read_all(mut bytes: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (tag, contents, rest) = read(bytes)?;
        out.push((tag, contents));
        bytes = rest;
    }
    Ok(out)
}

/// The contents of the element in `elements` tagged `tag`.
///
/// # Errors
/// No such element.
pub fn find<'a>(elements: &[(u8, &'a [u8])], tag: u8) -> Result<&'a [u8]> {
    elements
        .iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, contents)| *contents)
        .ok_or_else(|| protocol_error(format!("no element tagged {tag:#04x}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_lengths_round_trip() {
        let short = tlv(OCTET_STRING, b"hi");
        assert_eq!(short, [0x04, 2, b'h', b'i']);
        let long = tlv(OCTET_STRING, &[7; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2c]);
        let (tag, contents, rest) = read(&long).expect("read");
        assert_eq!((tag, contents.len(), rest.len()), (OCTET_STRING, 300, 0));
        let two = [short.clone(), tlv(NULL, &[])].concat();
        let all = read_all(&two).expect("all");
        assert_eq!(all, vec![(OCTET_STRING, &b"hi"[..]), (NULL, &[][..])]);
        assert_eq!(find(&all, NULL).expect("null"), &[]);
        assert!(find(&all, INTEGER).is_err());
        assert_eq!(context(5, true), 0xa5);
        assert_eq!(context(9, false), 0x89);
    }

    #[test]
    fn integers_are_the_shortest_twos_complement() {
        for (value, bytes) in [
            (0, vec![0x00]),
            (1, vec![0x01]),
            (127, vec![0x7f]),
            (128, vec![0x00, 0x80]),
            (-1, vec![0xff]),
            (-129, vec![0xff, 0x7f]),
            (65_535, vec![0x00, 0xff, 0xff]),
        ] {
            assert_eq!(integer(value), bytes, "{value}");
            assert_eq!(read_integer(&bytes).expect("read"), value, "{value}");
        }
        assert!(read_integer(&[]).is_err());
        assert!(read_integer(&[0; 9]).is_err());
    }

    #[test]
    fn what_is_not_ber_is_refused() {
        assert!(read(&[]).is_err(), "no tag");
        assert!(read(&[0x04]).is_err(), "no length");
        assert!(read(&[0x1f, 0x01, 0x00]).is_err(), "multi-byte tag");
        assert!(read(&[0x04, 0x80]).is_err(), "indefinite");
        assert!(read(&[0x04, 0x85, 0, 0, 0, 0, 0]).is_err(), "too wide");
        assert!(
            read(&[0x04, 0x82, 0x01]).is_err(),
            "cut short in the length"
        );
        assert!(read(&[0x04, 0x05, 1, 2]).is_err(), "past the end");
    }
}
