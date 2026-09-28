# xmip-core-transport-iec-61850

IEC 61850 transport: MMS over ISO transport on TCP — initiate, a write and a read of a domain variable as an octet string, conclude — and GOOSE, the publisher's frame on raw Ethernet with a Stream as its data set. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Receive Location reads, and a Send Location writes, on an association initiated once per server and kept (`transport::Pool`); one the server closed is replaced. Until 2026-09-28 every read and write connected, initiated and concluded.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
