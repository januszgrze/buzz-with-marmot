use std::{
    io::Write,
    process::{Command as ProcessCommand, Stdio},
};

use buzz_marmot_ipc::{
    decode_payload, encode_frame, Command, FrameDecoder, Request, Response, ResponseOutcome,
    ResponseResult, SecretBytes32,
};

#[test]
fn subprocess_stdout_and_stderr_never_echo_initialization_secrets() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let database_path = directory.path().join("marmot-path-canary.sqlite3");
    let database_path_text = database_path.to_string_lossy().into_owned();

    let mut child = ProcessCommand::new(env!("CARGO_BIN_EXE_buzz-marmot-sidecar"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn Marmot sidecar");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let requests = [
        Request::new(
            1,
            Command::Handshake {
                client_name: "process-secret-canary-test".into(),
            },
        ),
        Request::new(
            2,
            Command::Initialize {
                database_path: database_path_text.clone(),
                database_key: SecretBytes32::new([0xA5; 32]),
                account_secret_key: SecretBytes32::new([1; 32]),
                relay_endpoint: "wss://relay.example".into(),
            },
        ),
        Request::new(3, Command::Shutdown),
    ];
    for request in requests {
        stdin
            .write_all(&encode_frame(&request).expect("encode request"))
            .expect("write request");
    }
    drop(stdin);

    let output = child.wait_with_output().expect("wait for sidecar");
    assert!(output.status.success());
    assert!(
        output.stderr.is_empty(),
        "stderr must stay sanitized and empty"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("marmot-path-canary"));
    assert!(!stdout.contains("165,165,165,165"));
    assert!(!stdout.contains("1,1,1,1,1,1,1,1"));

    let mut decoder = FrameDecoder::new();
    let frames = decoder.push(&output.stdout).expect("decode sidecar output");
    assert_eq!(frames.len(), 3);
    let responses = frames
        .iter()
        .map(|payload| decode_payload::<Response>(payload).expect("decode response"))
        .collect::<Vec<_>>();
    assert!(matches!(
        responses[0].outcome,
        ResponseOutcome::Success { .. }
    ));
    assert!(matches!(
        responses[1].outcome,
        ResponseOutcome::Success { .. }
    ));
    assert!(matches!(
        responses[2].outcome,
        ResponseOutcome::Success {
            result: ResponseResult::ShuttingDown
        }
    ));
}
