//! The guardian-approval relay (`packages/perch-relay`), run as its own
//! process and spoken to over HTTP, as a guardian's wallet and a collector
//! would: the relay's `perch-relay` command with enforcing simulation
//! against the same RPC.

use std::io::{BufRead as _, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use stellar_xdr::{Limits, ReadXdr, ScVal, SorobanAuthorizationEntry, WriteXdr};

pub struct Relay {
    child: Child,
    pub url: String,
}

/// One approval as `GET /approvals/:digest` serves it.
pub struct Relayed {
    pub guardian: String,
    pub entry: SorobanAuthorizationEntry,
    pub args: Vec<ScVal>,
    pub admitted_by: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Wire {
    guardian: String,
    entry: String,
    args: Vec<String>,
    admitted_by: String,
}

fn cli() -> PathBuf {
    std::env::var_os("PERCH_RELAY_CLI")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packages/perch-relay/dist/cli.js")
        })
}

impl Relay {
    /// Start a relay for `controller` that admits entries by enforcing
    /// simulation through `rpc_url`, on a free local port.
    pub fn start(controller: &str, passphrase: &str, rpc_url: &str) -> Result<Self> {
        let cli = cli();
        if !cli.exists() {
            bail!(
                "{} is missing: npm --prefix packages/perch-relay ci && npm --prefix packages/perch-relay run build",
                cli.display()
            );
        }
        let mut child = Command::new("node")
            .arg(&cli)
            .args(["--controller", controller])
            .args(["--network-passphrase", passphrase])
            .args(["--rpc-url", rpc_url])
            .args(["--port", "0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("start the relay (node)")?;
        let mut url = String::new();
        BufReader::new(child.stdout.take().context("relay stdout")?)
            .read_line(&mut url)
            .context("read the relay's URL")?;
        let url = url.trim().to_string();
        if !url.starts_with("http://") {
            let _ = child.kill();
            bail!("the relay did not start: {url:?}");
        }
        eprintln!("  relay at {url}");
        Ok(Self { child, url })
    }

    /// `PUT /approvals/:digest`: the status and body.
    pub fn put(
        &self,
        digest: &str,
        entry: &SorobanAuthorizationEntry,
        args: &[ScVal],
    ) -> Result<(u16, String)> {
        let body = serde_json::json!({
            "entry": entry.to_xdr_base64(Limits::none())?,
            "args": args
                .iter()
                .map(|a| a.to_xdr_base64(Limits::none()))
                .collect::<std::result::Result<Vec<_>, _>>()?,
        });
        match ureq::put(&format!("{}/approvals/{digest}", self.url))
            .set("content-type", "application/json")
            .send_string(&body.to_string())
        {
            Ok(r) => Ok((r.status(), r.into_string()?)),
            Err(ureq::Error::Status(code, r)) => Ok((code, r.into_string()?)),
            Err(e) => Err(e).context("PUT the approval"),
        }
    }

    /// `GET /approvals/:digest`.
    pub fn get(&self, digest: &str) -> Result<Vec<Relayed>> {
        #[derive(Deserialize)]
        struct Body {
            approvals: Vec<Wire>,
        }
        let body: Body = ureq::get(&format!("{}/approvals/{digest}", self.url))
            .call()
            .context("GET the approvals")?
            .into_json()?;
        body.approvals
            .into_iter()
            .map(|w| {
                Ok(Relayed {
                    guardian: w.guardian,
                    entry: SorobanAuthorizationEntry::from_xdr_base64(&w.entry, Limits::none())?,
                    args: w
                        .args
                        .iter()
                        .map(|a| ScVal::from_xdr_base64(a, Limits::none()))
                        .collect::<std::result::Result<_, _>>()?,
                    admitted_by: w.admitted_by,
                })
            })
            .collect()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
