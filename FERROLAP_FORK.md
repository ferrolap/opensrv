# Ferrolap fork of opensrv

This repository is a fork of [databendlabs/opensrv](https://github.com/databendlabs/opensrv),
maintained by the Ferrolap project. The original code is Copyright 2021 Datafuse Labs
and is licensed under the Apache License, Version 2.0 (see `LICENSE`). The license and
the original copyright notices are unchanged.

Ferrolap pins this fork by git revision. Branches are based on upstream commit
`de6178b204b3b74ea471426a6fa811835d61b4cd`.

## Changes on `ferrolap/m5-auth` (`opensrv-mysql` only)

Modified files: `mysql/src/lib.rs`, `mysql/src/commands.rs`, `mysql/src/resultset.rs`, `mysql/src/writers.rs`.

1. Authentication failure is reported as `ER_ACCESS_DENIED_ERROR` (1045 / SQLSTATE 28000)
   with the text `Access denied for user '<user>' (using password: YES|NO)`, instead of
   1698. The text does not depend on whether the user exists.
2. Commands the command parser does not recognize (including `COM_CHANGE_USER`,
   `COM_RESET_CONNECTION` and `COM_PROCESS_KILL`) get `ER_UNKNOWN_COM_ERROR`
   (1047 / 08S01) instead of an OK packet.
3. AuthSwitch (Ferrolap architect ruling, 2026-11-27 03:44 EST): whenever the plugin
   named in the client's first packet differs from the expected plugin, the server sends
   AuthSwitchRequest whether or not the first auth response is empty. The first-packet
   data is discarded and only the switched answer is verified. A client without
   `CLIENT_PLUGIN_AUTH` is treated as `mysql_native_password` (no switch). The decision
   depends only on the client's plugin name, not on the user. The request carries the
   shim's `salt()`. (Commit `f42ffc2f` widened the rule differently and was reverted in
   `a48d8682`; this replaces both.)
   Also: when the first packet has `CLIENT_PLUGIN_AUTH` but not
   `CLIENT_SECURE_CONNECTION`, consume the NUL that terminates the auth
   response before parsing the database and plugin fields. Otherwise the
   plugin name is read as empty and a native first packet is wrongly switched.


4. Greeting capabilities (Ferrolap M5 P6 / architect Q5): the server greeting
   also advertises `CLIENT_TRANSACTIONS`, `CLIENT_MULTI_RESULTS`, and
   `CLIENT_MULTI_STATEMENTS`. `CLIENT_DEPRECATE_EOF` stays set; `CLIENT_SSL`
   is still off when TLS is not configured. The default collation is unchanged
   (still 33).
   `QueryResultWriter::client_capabilities()` exposes the flags the client
   declared, so the shim can reject a multi-statement `COM_QUERY` when the
   client did not set `CLIENT_MULTI_STATEMENTS`.
   `QueryResultWriter::error_with` / `RowWriter::finish_error_with` write an
   ERR packet with an explicit errno and SQLSTATE, for mapped codes that are
   not `ErrorKind` variants (for example timeout 3024).

Tests for these changes: `mysql/tests/it/ferrolap.rs`
(`cargo test -p opensrv-mysql --test it ferrolap`).
