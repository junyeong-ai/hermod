//! IPC round-trip: spawn a fake server that echoes a `status` result, connect with
//! `IpcClient`, call it, validate result.

use hermod_core::AgentId;
use hermod_protocol::ipc::{IpcClient, IpcServer, Response, ResponsePayload, methods};
use hermod_transport::{UnixIpcListener, unix};
use std::str::FromStr;

fn tmp_sock() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("hermod-ipc-test-{}.sock", ulid::Ulid::new()));
    p
}

#[tokio::test]
async fn status_call_roundtrip() {
    let sock = tmp_sock();
    let listener = UnixIpcListener::bind(&sock).await.unwrap();

    let server = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let mut server = IpcServer::new(stream);
        let req = server.next_request().await.unwrap().unwrap();
        assert_eq!(req.method, methods::method::STATUS_GET);

        let res = methods::StatusGetResult {
            version: "0.1.0".into(),
            agent_id: AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap(),
            alias: None,
            pending_messages: 3,
            peer_count: 0,
            uptime_secs: 12,
            attached_sessions: 1,
            schema_version: "1".into(),
        };
        let resp = Response {
            jsonrpc: hermod_protocol::ipc::JsonRpc2,
            id: req.id,
            payload: ResponsePayload::Ok {
                result: serde_json::to_value(&res).unwrap(),
            },
        };
        server.send_response(resp).await.unwrap();
    });

    // Use raw unix::connect instead of IpcClient::connect_unix so we get the
    // IpcError conversion for free in the client call path.
    let stream = unix::connect(&sock).await.unwrap();
    let mut client = {
        use hermod_protocol::ipc::ClientCodec;
        use tokio_util::codec::Framed;
        let framed = Framed::new(stream, ClientCodec::default());
        RawClient { framed }
    };

    use futures::{SinkExt, StreamExt};
    let id = hermod_protocol::ipc::Id::from_ulid();
    let req = hermod_protocol::ipc::Request::new(id.clone(), methods::method::STATUS_GET, None);
    client.framed.send(req).await.unwrap();
    let resp = client.framed.next().await.unwrap().unwrap();
    assert_eq!(resp.id, id);
    match resp.payload {
        ResponsePayload::Ok { result } => {
            let status: methods::StatusGetResult = serde_json::from_value(result).unwrap();
            assert_eq!(status.pending_messages, 3);
        }
        ResponsePayload::Err { error } => panic!("unexpected error: {error:?}"),
    }

    server.await.unwrap();
}

struct RawClient {
    framed: tokio_util::codec::Framed<
        hermod_transport::UnixIpcStream,
        hermod_protocol::ipc::ClientCodec,
    >,
}

#[tokio::test]
async fn ipc_client_status_through_real_connect() {
    let sock = tmp_sock();
    let listener = UnixIpcListener::bind(&sock).await.unwrap();

    let server = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let mut server = IpcServer::new(stream);
        let req = server.next_request().await.unwrap().unwrap();
        let res = methods::StatusGetResult {
            version: "0.1.0".into(),
            agent_id: AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap(),
            alias: None,
            pending_messages: 0,
            peer_count: 0,
            uptime_secs: 0,
            attached_sessions: 0,
            schema_version: "1".into(),
        };
        server
            .send_response(Response {
                jsonrpc: hermod_protocol::ipc::JsonRpc2,
                id: req.id,
                payload: ResponsePayload::Ok {
                    result: serde_json::to_value(&res).unwrap(),
                },
            })
            .await
            .unwrap();
    });

    let mut client = IpcClient::connect_unix(&sock).await.unwrap();
    let status: methods::StatusGetResult = client
        .call_noparams(methods::method::STATUS_GET)
        .await
        .unwrap();
    assert_eq!(status.version, "0.1.0");
    server.await.unwrap();
}
