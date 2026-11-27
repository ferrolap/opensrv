// Copyright 2026 the Ferrolap authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tests for the Ferrolap fork changes described in FERROLAP_FORK.md.

use std::io;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use opensrv_mysql::{
    AsyncMysqlIntermediary, AsyncMysqlShim, InitWriter, ParamParser, QueryResultWriter,
    StatementMetaWriter,
};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CLIENT_PROTOCOL_41: u32 = 1 << 9;
const CLIENT_SECURE_CONNECTION: u32 = 1 << 15;
const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;

/// Per-connection salt the shim hands out; differs from upstream's fixed salt.
const SHIM_SALT: [u8; 20] = *b"ferrolap-test-salt-1";
const UPSTREAM_FIXED_SALT: &[u8; 20] = b";X,po_k}>o6^Wz!/kM}N";

/// Recorded `(auth_plugin, auth_data)` pairs.
type Calls = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Accepts exactly the auth response `[0x42; 20]` and records every call.
struct Shim {
    calls: Calls,
}

#[async_trait]
impl<W: AsyncWrite + Send + Unpin> AsyncMysqlShim<W> for Shim {
    type Error = io::Error;

    fn salt(&self) -> [u8; 20] {
        SHIM_SALT
    }

    async fn authenticate(
        &self,
        auth_plugin: &str,
        _username: &[u8],
        _salt: &[u8],
        auth_data: &[u8],
    ) -> bool {
        self.calls
            .lock()
            .unwrap()
            .push((auth_plugin.to_owned(), auth_data.to_vec()));
        auth_data == [0x42; 20]
    }

    async fn on_prepare<'a>(
        &'a mut self,
        _query: &'a str,
        info: StatementMetaWriter<'a, W>,
    ) -> io::Result<()> {
        info.reply(1, &[], &[]).await
    }

    async fn on_execute<'a>(
        &'a mut self,
        _id: u32,
        _params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        results.completed(Default::default()).await
    }

    async fn on_close<'a>(&'a mut self, _stmt: u32)
    where
        W: 'async_trait,
    {
    }

    async fn on_query<'a>(
        &'a mut self,
        _query: &'a str,
        results: QueryResultWriter<'a, W>,
    ) -> io::Result<()> {
        results.completed(Default::default()).await
    }

    async fn on_init<'a>(
        &'a mut self,
        _schema: &'a str,
        writer: InitWriter<'a, W>,
    ) -> io::Result<()> {
        writer.ok().await
    }
}

async fn start() -> (u16, Calls) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let shim_calls = Arc::clone(&calls);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, write) = stream.into_split();
        let _ = AsyncMysqlIntermediary::run_on(Shim { calls: shim_calls }, read, write).await;
    });
    (port, calls)
}

async fn read_packet(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let len = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    (header[3], payload)
}

async fn write_packet(stream: &mut TcpStream, seq: u8, payload: &[u8]) {
    let mut header = (payload.len() as u32).to_le_bytes();
    header[3] = seq;
    stream.write_all(&header).await.unwrap();
    stream.write_all(payload).await.unwrap();
}

fn handshake_response(plugin: &str, auth: &[u8]) -> Vec<u8> {
    handshake_response_with(
        CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH,
        "u",
        plugin,
        auth,
    )
}

fn handshake_response_with(capabilities: u32, user: &str, plugin: &str, auth: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&capabilities.to_le_bytes());
    body.extend_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    body.push(33);
    body.extend_from_slice(&[0u8; 23]);
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        body.push(auth.len() as u8);
        body.extend_from_slice(auth);
    } else {
        body.extend_from_slice(auth);
        body.push(0);
    }
    if capabilities & CLIENT_PLUGIN_AUTH != 0 {
        body.extend_from_slice(plugin.as_bytes());
        body.push(0);
    }
    body
}

/// Send `first`, expect an AuthSwitchRequest carrying the shim's salt, answer
/// with `switched`, and return the server's final packet.
async fn switch_and_answer(port: u16, first: Vec<u8>, switched: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _greeting = read_packet(&mut stream).await;
    write_packet(&mut stream, 1, &first).await;
    let (seq, payload) = read_packet(&mut stream).await;
    assert_eq!(seq, 2);
    assert_eq!(
        payload[0], 0xfe,
        "expected AuthSwitchRequest, got {payload:?}"
    );
    let name = b"mysql_native_password\0";
    assert!(payload[1..].starts_with(name));
    let salt = &payload[1 + name.len()..1 + name.len() + 20];
    assert_eq!(
        salt,
        SHIM_SALT.as_slice(),
        "AuthSwitchRequest must carry salt()"
    );
    assert_ne!(salt, UPSTREAM_FIXED_SALT.as_slice());
    write_packet(&mut stream, 3, switched).await;
    let (seq, answer) = read_packet(&mut stream).await;
    assert_eq!(seq, 4);
    answer
}

fn errno(payload: &[u8]) -> (u16, String) {
    assert_eq!(payload[0], 0xff, "expected ERR, got {payload:?}");
    let code = u16::from_le_bytes([payload[1], payload[2]]);
    assert_eq!(payload[3], b'#');
    (code, String::from_utf8(payload[4..9].to_vec()).unwrap())
}

/// Log in with a native response; returns the stream positioned after OK.
async fn login(port: u16, auth: &[u8]) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _greeting = read_packet(&mut stream).await;
    write_packet(
        &mut stream,
        1,
        &handshake_response("mysql_native_password", auth),
    )
    .await;
    let (seq, payload) = read_packet(&mut stream).await;
    assert_eq!(seq, 2);
    (stream, payload)
}

#[tokio::test]
async fn failed_authentication_is_1045_access_denied() {
    let (port, _) = start().await;
    let (_stream, payload) = login(port, &[0x11; 20]).await;
    let (code, state) = errno(&payload);
    assert_eq!(code, 1045);
    assert_eq!(state, "28000");
    let message = String::from_utf8_lossy(&payload[9..]).to_string();
    assert_eq!(message, "Access denied for user 'u' (using password: YES)");
}

#[tokio::test]
async fn auth_switch_still_follows_the_upstream_rule() {
    let (port, calls) = start().await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _greeting = read_packet(&mut stream).await;
    // Another plugin with an empty first response: upstream switches.
    write_packet(
        &mut stream,
        1,
        &handshake_response("caching_sha2_password", &[]),
    )
    .await;
    let (seq, payload) = read_packet(&mut stream).await;
    assert_eq!(seq, 2);
    assert_eq!(payload[0], 0xfe, "expected AuthSwitchRequest");
    assert!(payload[1..].starts_with(b"mysql_native_password\0"));
    write_packet(&mut stream, 3, &[0x42; 20]).await;
    let (seq, payload) = read_packet(&mut stream).await;
    assert_eq!(seq, 4);
    assert_eq!(payload[0], 0x00, "expected OK, got {payload:?}");
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "mysql_native_password");
    assert_eq!(calls[0].1, vec![0x42; 20]);
}

#[tokio::test]
async fn unrecognized_commands_are_1047_not_ok() {
    let (port, _) = start().await;
    let (mut stream, payload) = login(port, &[0x42; 20]).await;
    assert_eq!(payload[0], 0x00);
    // COM_PROCESS_KILL, COM_CHANGE_USER, COM_RESET_CONNECTION, then an unknown byte.
    for command in [
        vec![0x0c, 1, 0, 0, 0],
        vec![0x11, b'r', 0],
        vec![0x1f],
        vec![0xee],
    ] {
        write_packet(&mut stream, 0, &command).await;
        let (seq, payload) = read_packet(&mut stream).await;
        assert_eq!(seq, 1);
        assert_eq!(errno(&payload), (1047, "08S01".to_owned()), "{command:?}");
    }
    // The connection stays usable.
    write_packet(&mut stream, 0, &[0x0e]).await;
    let (_, payload) = read_packet(&mut stream).await;
    assert_eq!(payload[0], 0x00, "COM_PING should still be OK");
}

#[tokio::test]
async fn non_empty_answer_for_another_plugin_is_switched_and_discarded() {
    for user in ["u", "unknown-user"] {
        let (port, calls) = start().await;
        // A MySQL 8.x style first packet: caching_sha2_password with 32 bytes.
        // The [0x42; 20] prefix would pass if it were not discarded.
        let mut first_data = vec![0x42; 20];
        first_data.extend_from_slice(&[0x99; 12]);
        let first = handshake_response_with(
            CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH,
            user,
            "caching_sha2_password",
            &first_data,
        );
        let answer = switch_and_answer(port, first, &[0x42; 20]).await;
        assert_eq!(answer[0], 0x00, "{user}: expected OK, got {answer:?}");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "only the switched answer is verified");
        assert_eq!(
            calls[0],
            ("mysql_native_password".to_owned(), vec![0x42; 20])
        );
    }
}

#[tokio::test]
async fn first_packet_data_alone_never_logs_in_after_a_switch() {
    let (port, calls) = start().await;
    let first = handshake_response("caching_sha2_password", &[0x42; 20]);
    let answer = switch_and_answer(port, first, &[0x11; 20]).await;
    assert_eq!(answer[0], 0xff);
    assert_eq!(u16::from_le_bytes([answer[1], answer[2]]), 1045);
    assert_eq!(calls.lock().unwrap()[0].1, vec![0x11; 20]);
}

#[tokio::test]
async fn native_plugin_and_no_plugin_auth_are_verified_without_switch() {
    // Same plugin name: verified directly.
    let (port, calls) = start().await;
    let (_stream, payload) = login(port, &[0x42; 20]).await;
    assert_eq!(payload[0], 0x00);
    assert_eq!(calls.lock().unwrap().len(), 1);

    // No CLIENT_PLUGIN_AUTH: treated as mysql_native_password, no switch.
    let (port, calls) = start().await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _greeting = read_packet(&mut stream).await;
    let first = handshake_response_with(
        CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION,
        "u",
        "",
        &[0x42; 20],
    );
    write_packet(&mut stream, 1, &first).await;
    let (seq, payload) = read_packet(&mut stream).await;
    assert_eq!(seq, 2);
    assert_eq!(
        payload[0], 0x00,
        "expected OK without a switch, got {payload:?}"
    );
    assert_eq!(calls.lock().unwrap()[0].1, vec![0x42; 20]);
}

#[tokio::test]
async fn nul_terminated_native_first_packet_is_not_switched() {
    let (port, calls) = start().await;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _greeting = read_packet(&mut stream).await;
    // PROTOCOL_41 + PLUGIN_AUTH, no SECURE_CONNECTION: auth data is NUL-terminated.
    let first = handshake_response_with(
        CLIENT_PROTOCOL_41 | CLIENT_PLUGIN_AUTH,
        "u",
        "mysql_native_password",
        &[0x42; 20],
    );
    write_packet(&mut stream, 1, &first).await;
    let (seq, payload) = read_packet(&mut stream).await;
    assert_eq!(seq, 2);
    assert_eq!(
        payload[0], 0x00,
        "same plugin must be verified without AuthSwitch, got {payload:?}"
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "mysql_native_password");
    assert_eq!(calls[0].1, vec![0x42; 20]);
}

#[tokio::test]
async fn nul_terminated_other_plugin_is_still_switched() {
    let (port, calls) = start().await;
    let first = handshake_response_with(
        CLIENT_PROTOCOL_41 | CLIENT_PLUGIN_AUTH,
        "u",
        "caching_sha2_password",
        &[0x99; 20],
    );
    let answer = switch_and_answer(port, first, &[0x42; 20]).await;
    assert_eq!(answer[0], 0x00, "expected OK after switch, got {answer:?}");
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, vec![0x42; 20]);
}
