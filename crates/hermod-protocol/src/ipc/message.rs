use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::error::RpcError;

/// The constant `"2.0"` string per JSON-RPC 2.0. Validated on deserialize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonRpc2;

impl Serialize for JsonRpc2 {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str("2.0")
    }
}

impl<'de> Deserialize<'de> for JsonRpc2 {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        if s != "2.0" {
            return Err(serde::de::Error::custom(format!(
                "expected jsonrpc \"2.0\", got {s:?}"
            )));
        }
        Ok(JsonRpc2)
    }
}

/// JSON-RPC request identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    Num(i64),
    Str(String),
    #[serde(deserialize_with = "deserialize_null")]
    Null,
}

fn deserialize_null<'de, D: Deserializer<'de>>(de: D) -> Result<(), D::Error> {
    use serde::de::IgnoredAny;
    let _ = IgnoredAny::deserialize(de)?;
    Ok(())
}

impl Id {
    pub fn from_ulid() -> Self {
        Id::Str(ulid::Ulid::new().to_string())
    }
}

/// JSON-RPC 2.0 request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: JsonRpc2,
    pub id: Id,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Request {
    pub fn new(id: Id, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JsonRpc2,
            id,
            method: method.into(),
            params,
        }
    }
}

/// JSON-RPC 2.0 response payload: either `result` or `error`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponsePayload {
    Ok { result: Value },
    Err { error: RpcError },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: JsonRpc2,
    pub id: Id,
    #[serde(flatten)]
    pub payload: ResponsePayload,
}

impl Response {
    pub fn ok(id: Id, result: Value) -> Self {
        Self {
            jsonrpc: JsonRpc2,
            id,
            payload: ResponsePayload::Ok { result },
        }
    }

    pub fn err(id: Id, error: RpcError) -> Self {
        Self {
            jsonrpc: JsonRpc2,
            id,
            payload: ResponsePayload::Err { error },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req = Request::new(
            Id::Str("abc".into()),
            "message.send",
            Some(serde_json::json!({ "to": "bob" })),
        );
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back.method, "message.send");
    }

    #[test]
    fn response_ok_and_err_serialize_disjoint() {
        let ok = Response::ok(Id::Num(1), serde_json::json!({ "status": "ok" }));
        let s = serde_json::to_string(&ok).unwrap();
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));

        let err = Response::err(
            Id::Num(2),
            RpcError::new(super::super::error::code::NOT_FOUND, "nope"),
        );
        let s = serde_json::to_string(&err).unwrap();
        assert!(s.contains("\"error\""));
        assert!(!s.contains("\"result\""));
    }

    #[test]
    fn rejects_wrong_jsonrpc_version() {
        let s = r#"{"jsonrpc":"1.0","id":1,"method":"foo"}"#;
        assert!(serde_json::from_str::<Request>(s).is_err());
    }
}
