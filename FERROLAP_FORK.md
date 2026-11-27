# Ferrolap fork of opensrv

This repository is a fork of [databendlabs/opensrv](https://github.com/databendlabs/opensrv),
maintained by the Ferrolap project. The original code is Copyright 2021 Datafuse Labs
and is licensed under the Apache License, Version 2.0 (see `LICENSE`). The license and
the original copyright notices are unchanged.

Ferrolap pins this fork by git revision. Branches are based on upstream commit
`de6178b204b3b74ea471426a6fa811835d61b4cd`.

## Changes on `ferrolap/m5-auth` (`opensrv-mysql` only)

Modified file: `mysql/src/lib.rs`.

1. Authentication failure is reported as `ER_ACCESS_DENIED_ERROR` (1045 / SQLSTATE 28000)
   with the text `Access denied for user '<user>' (using password: YES|NO)`, instead of
   1698. The text does not depend on whether the user exists.
2. AuthSwitch is also sent when a client that set `CLIENT_PLUGIN_AUTH` answered the
   greeting for a different plugin than the one the shim expects (for example a MySQL
   8.x client defaulting to `caching_sha2_password`). Upstream switched only when the
   first auth response was empty.
3. Commands the command parser does not recognize (including `COM_CHANGE_USER`,
   `COM_RESET_CONNECTION` and `COM_PROCESS_KILL`) get `ER_UNKNOWN_COM_ERROR`
   (1047 / 08S01) instead of an OK packet.

Tests for these changes: `mysql/tests/it/ferrolap.rs`
(`cargo test -p opensrv-mysql --test it ferrolap`).
