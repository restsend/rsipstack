use super::{bounded, free_addr, log_dir, sdp, until, Stack};
use rsipstack::{
    dialog::{dialog::DialogState, invitation::InviteOption},
    sip::{Method, Uri},
};
use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::process::{Child, Command};
mod extended;
mod prack_uas;
mod registration;
mod subscription;

struct Sipp {
    child: Child,
    pub uri: Uri,
    log: PathBuf,
}

impl Sipp {
    async fn start(scenario: &str, transport: &str, dir: &Path, local_uri: &Uri) -> Self {
        Self::start_with_keys(scenario, transport, dir, local_uri, &[]).await
    }

    async fn start_with_keys(
        scenario: &str,
        transport: &str,
        dir: &Path,
        local_uri: &Uri,
        keys: &[(&str, String)],
    ) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let binary = std::env::var_os("SIPP_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("target/interop/sipp"));
        assert!(
            binary.is_file(),
            "SIPp not found: {}. Run bash scripts/interop/build-sipp.sh or set SIPP_BIN",
            binary.display()
        );
        let addr = free_addr(transport);
        let uri: Uri = format!("sip:sipp@{addr};transport={transport}")
            .parse()
            .unwrap();
        let log = dir.join("sipp.actions.log");
        // SIPp parses response status codes before expanding runtime -key
        // values. Render these fixed test parameters before loading the XML.
        let source = root.join(format!("tests/interop/scenarios/{scenario}.xml"));
        let mut xml = std::fs::read_to_string(source).unwrap();
        for (key, value) in keys {
            xml = xml.replace(&format!("[{key}]"), value);
        }
        let rendered = dir.join("scenario.xml");
        std::fs::write(&rendered, xml).unwrap();
        // This scenario receives the same ACK twice on purpose. SIPp's UDP
        // duplicate detector would otherwise consume it before the XML step.
        let duplicate_flags = if matches!(scenario, "duplicate_200" | "prack_lost_response") {
            vec!["-nr"]
        } else {
            vec![]
        };
        let child = Command::new(binary)
            .args(if scenario.starts_with("prack_uas") {
                vec![local_uri.host_with_port.to_string()]
            } else {
                vec![]
            })
            .args(duplicate_flags)
            .current_dir(dir)
            .arg("-sf")
            .arg(rendered)
            .args(["-i", "127.0.0.1", "-p"])
            .arg(addr.port().to_string())
            .args([
                "-t",
                if transport == "udp" { "u1" } else { "t1" },
                "-m",
                "1",
                "-recv_timeout",
                "5000",
                "-timeout",
                "15s",
                "-timeout_error",
                "-nostdin",
                "-trace_msg",
                "-message_file",
                "sipp.messages.log",
                "-trace_err",
                "-error_file",
                "sipp.errors.log",
                "-trace_screen",
                "-screen_file",
                "sipp.screen.log",
                "-trace_logs",
                "-log_file",
                "sipp.actions.log",
                "-key",
                "rsip_uri",
            ])
            .arg(local_uri.to_string())
            .args(["-key", "sipp_uri"])
            .arg(uri.to_string())
            .stdin(Stdio::null())
            .stdout(File::create(dir.join("sipp.stdout.log")).unwrap())
            .stderr(File::create(dir.join("sipp.stderr.log")).unwrap())
            .kill_on_drop(true)
            .spawn()
            .expect("start SIPp");
        let mut peer = Self { child, uri, log };
        // UDP has no connect handshake. Poll until the child owns its selected
        // loopback port; do not depend on a machine-specific startup sleep.
        until("SIPp listener", || {
            assert!(
                peer.child.try_wait().unwrap().is_none(),
                "SIPp exited during startup; inspect its logs"
            );
            let result = if transport == "udp" {
                std::net::UdpSocket::bind(addr).map(|_| ())
            } else {
                std::net::TcpListener::bind(addr).map(|_| ())
            };
            match result {
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Some(()),
                Err(e) => panic!("listener probe: {e}"),
                Ok(()) => None,
            }
        })
        .await;
        peer
    }

    async fn marker(&mut self, marker: &str) {
        until(marker, || {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "SIPp exited before marker {marker}; inspect its logs"
            );
            std::fs::read_to_string(&self.log)
                .unwrap_or_default()
                .contains(marker)
                .then_some(())
        })
        .await;
    }

    async fn finish(mut self) {
        let status = bounded("SIPp result", self.child.wait()).await.unwrap();
        assert_eq!(
            status.code(),
            Some(0),
            "SIPp failed ({status}); inspect sipp.errors.log and sipp.messages.log"
        );
    }

    async fn guarded<T>(
        &mut self,
        description: &str,
        future: impl std::future::Future<Output = T>,
    ) -> T {
        let pending = bounded(description, future);
        tokio::pin!(pending);
        tokio::select! {
            result = &mut pending => result,
            status = self.child.wait() => {
                let status = status.expect("wait for SIPp");
                assert!(status.success(), "SIPp exited with {status} while waiting for {description}; inspect its logs");
                pending.await
            }
        }
    }
}

async fn scenario(name: &str, transport: &str, kind: &str) {
    let dir = log_dir(name);
    let stack = Stack::start(transport, &dir).await;
    let mut peer = Sipp::start(kind, transport, &dir, &stack.uri).await;
    let (dialog, invite) = stack
        .layer
        .do_invite_async(
            InviteOption {
                caller: stack.uri.clone(),
                callee: peer.uri.clone(),
                contact: stack.uri.clone(),
                offer: Some(sdp()),
                ..Default::default()
            },
            stack.sender.clone(),
        )
        .unwrap();
    if kind == "cancel" {
        stack.wire.response(false, Method::Invite, 180).await;
        bounded("CANCEL", dialog.cancel()).await.unwrap();
        stack.wire.response(false, Method::Cancel, 200).await;
        stack.wire.response(false, Method::Invite, 487).await;
    }
    peer.guarded("INVITE", invite).await.unwrap().unwrap();
    if kind == "duplicate_200" {
        peer.marker("SECOND_ACK_RECEIVED").await;
        bounded("BYE", dialog.bye()).await.unwrap();
        stack.wire.response(false, Method::Bye, 200).await;
    } else if kind == "wrong_tag_bye" {
        // Release the scenario after the INVITE driver registered the dialog.
        let response = bounded("OPTIONS", dialog.request(Method::Options, None, None))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status_code.code(), 200);
        peer.marker("BAD_TAGS_REJECTED").await;
        assert!(matches!(dialog.state(), DialogState::Confirmed(..)));
        assert!(!stack
            .states
            .lock()
            .unwrap()
            .iter()
            .any(|s| matches!(s, DialogState::Terminated(..))));
        // A second OPTIONS authorizes the valid BYE, after checking both 481s.
        let response = bounded("OPTIONS", dialog.request(Method::Options, None, None))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status_code.code(), 200);
        stack.wire.response(true, Method::Bye, 200).await;
    }
    peer.finish().await;
    stack
        .state("termination", |s| matches!(s, DialogState::Terminated(..)))
        .await;
    until("empty dialog registry", || {
        stack.layer.is_empty().then_some(())
    })
    .await;
    let states = stack.states.lock().unwrap();
    assert_eq!(
        states
            .iter()
            .filter(|s| matches!(s, DialogState::Terminated(..)))
            .count(),
        1
    );
    assert_eq!(
        states
            .iter()
            .filter(|s| matches!(s, DialogState::Confirmed(..)))
            .count(),
        usize::from(kind != "cancel")
    );
    if kind == "cancel" {
        assert_eq!(stack.wire.requests(Method::Bye), 0);
    }
    std::fs::write(
        dir.join("PASS"),
        format!("{name}: {kind} over {transport}\n"),
    )
    .unwrap();
}

macro_rules! sipp_case {
    ($name:ident, $transport:literal, $kind:literal) => {
        #[tokio::test]
        #[ignore = "requires SIPp; use scripts/interop/run.sh sipp"]
        async fn $name() {
            scenario(stringify!($name), $transport, $kind).await;
        }
    };
}
sipp_case!(udp_duplicate_200, "udp", "duplicate_200");
sipp_case!(tcp_duplicate_200, "tcp", "duplicate_200");
sipp_case!(udp_wrong_tag_bye, "udp", "wrong_tag_bye");
sipp_case!(tcp_wrong_tag_bye, "tcp", "wrong_tag_bye");
sipp_case!(udp_cancel, "udp", "cancel");
sipp_case!(tcp_cancel, "tcp", "cancel");
