# xmip-core-transport-iec-61850

IEC 61850 transport: MMS over ISO transport on TCP — initiate, a write and a read of a domain variable as an octet string, conclude — and GOOSE, the publisher's frame on raw Ethernet with a Stream as its data set. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Receive Location reads, and a Send Location writes, on an association initiated once per server and kept (`transport::Pool`); one the server closed is replaced. Until 2026-09-28 every read and write connected, initiated and concluded.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Acknowledgement

A receive is an MMS read of the variable, which consumes nothing at the
server. Its verdict therefore has nothing to tell the server, whichever it is:
a receive cycle that did not complete loses nothing, and the next read finds
the variable again. The variable's bytes arrive whole.

## The declaration

What a Location of this technology is configured with is two `const`s in its `declaration` module, `src/declaration.rs`, beside the code, which `Configured` reads (ADR-0064, amendment 2026-11-26): `declaration::SETTINGS`, `domain`, `item` and `timeout`, and `SCHEMES`, `iec61850`. The variable `domain` and `item` default to, `STREAM_DOMAIN` and `STREAM_ITEM`, is there too, and the code reads it from there. Built with its `declaration` feature alone (`--no-default-features --features declaration`), the crate is those and nothing more: its code and every crate the code is built on — the cotp and ethernet technologies it rides on and the estate's X.690 among them — are behind the default feature. So the library the surfaces load carries it without the code, through the gathering crate xmip-core-declaration (open problem 48), and the language server and the desktop suggest and check an IEC 61850 Location's settings though no node in their process loaded the technology. `test/Declaration.Test.ps1` in the estate holds that the declaration builds nothing the transport capability does not.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
