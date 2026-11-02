//! `herdr-app rex-core connect`: herdr-core's `hc connect` protocol
//! (schema/README.md in herdr-core) on stdin and stdout, served by a Rex
//! server. The app runs it in place of `hc connect`, so the window keeps
//! talking to a core while Rex runs the terminals.
//!
//! - A herdr terminal is a Rex terminal block. Every terminal block in every
//!   Rex session is listed.
//! - A herdr space is a Rex session, a tab is one of its windows, and the
//!   panes are the window's layout: the `herdr-app` document is Rex's view
//!   (mirror.rs). Terminals started outside any space wait in a session
//!   labelled `herdr`.
//! - Addresses (`t7`), labels, keep flags and what the layout has that Rex
//!   doesn't live in `rex/` in the app's home (store.rs).
//! - An attach is a Rex data connection. Its Ghostty snapshot is painted as
//!   VT (snapshot.rs); Rex's own messages are taken out of the output (stream.rs).
//!   Typing, size and colors go back through block methods.

mod control;
mod layout;
mod mirror;
mod snapshot;
mod store;
mod stream;
mod ws;

use crate::hc::{CLOSE, CREDIT, DATA, FACTS, FOCUS, RESIZE};
use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use control::Control;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TERMINAL: &str = "com.superlogical.terminal";
const SHELL: &str = "com.superlogical.terminal.shell";
const DATA_PROTOCOL: &str = "rex.data.terminal.v1";
/// What the app calls; the rest answer `unsupported`.
const METHODS: &[&str] = &[
    "hello", "server.status", "terminal.run", "terminal.list", "terminal.get", "terminal.kill", "terminal.keep",
    "terminal.label", "terminal.read", "terminal.attach", "terminal.send", "terminal.interrupt", "doc.get", "doc.set",
    "events.subscribe", "machine.list",
];

pub fn main(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        // `core_bin::version` wants `hc X.Y.Z`; `hc::check` wants at least the app's minimum.
        Some("-V" | "--version" | "version") => {
            println!("hc {}", crate::hc::core_min());
            0
        }
        Some("connect") => match serve() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("herdr-app rex-core: {e:#}");
                1
            }
        },
        _ => {
            eprintln!("usage: herdr-app rex-core connect\n\nServes herdr-core's `hc connect` protocol from a Rex server.");
            2
        }
    }
}

fn serve() -> Result<()> {
    let mut input = BufReader::new(std::io::stdin().lock());
    let mut stdout = std::io::stdout().lock();
    let mut line = String::new();
    input.read_line(&mut line)?;
    let hello: Value = serde_json::from_str(&line).context("expected a hello")?;
    let id = hello["id"].clone();
    let bridge = match Bridge::start() {
        Ok(b) => b,
        Err(e) => {
            let error = rpc_error("unavailable", &format!("cannot use Rex: {e:#}"));
            writeln!(stdout, "{}", json!({"jsonrpc": "2.0", "id": id, "error": error}))?;
            return Err(e);
        }
    };
    writeln!(stdout, "{}", json!({"jsonrpc": "2.0", "id": id, "result": bridge.hello()}))?;
    stdout.flush()?;
    drop(stdout);

    let frames = bridge.frames.take();
    std::thread::Builder::new().name("rex-out".into()).spawn(move || {
        let mut stdout = std::io::stdout().lock();
        for frame in frames.into_iter().flatten() {
            if stdout.write_all(&frame).and_then(|_| stdout.flush()).is_err() {
                break;
            }
        }
        // The app is gone.
        std::process::exit(0);
    })?;
    let events = bridge.events.take().ok_or_else(|| anyhow!("no event stream"))?;
    let b = bridge.clone();
    std::thread::Builder::new().name("rex-events".into()).spawn(move || {
        for event in events {
            b.on_event(&event);
        }
        // Rex went away: so does this core, and the app connects again.
        eprintln!("herdr-app rex-core: lost the Rex server");
        std::process::exit(1);
    })?;

    while let Some((channel, kind, payload)) = crate::hc::read_frame(&mut input) {
        if channel == 0 {
            if kind == DATA {
                let b = bridge.clone();
                std::thread::spawn(move || b.request(&payload));
            }
            continue;
        }
        bridge.stream_frame(channel, kind, payload);
    }
    Ok(())
}

fn rpc_error(kind: &str, message: &str) -> Value {
    json!({"code": -32000, "message": message, "data": {"kind": kind}})
}

/// A herdr error for a failed Rex call.
fn rex_error(e: &anyhow::Error) -> Value {
    let kind = match control::error_code(e) {
        Some("not_found" | "session_not_found") => "not_found",
        Some("unavailable") => "unavailable",
        Some("conflict") => "conflict",
        Some("bad_request") => "invalid",
        _ => "internal",
    };
    rpc_error(kind, &format!("{e:#}"))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or_default()
}

/// Rex IDs are UUIDv7: their first 48 bits are when they were made.
fn id_ms(id: &str) -> Option<u64> {
    let hex: String = id.split_once(':')?.1.chars().filter(|c| *c != '-').take(12).collect();
    u64::from_str_radix(&hex, 16).ok()
}

struct Term {
    session: String,
    block: String,
    record: Value,
    /// Rex program status records by ID; the root record's is "".
    status: BTreeMap<String, Value>,
}

/// One attach channel.
struct View {
    ops: mpsc::Sender<Op>,
    data: Arc<Mutex<Option<ws::Writer>>>,
}

enum Op {
    Input(Vec<u8>),
    Size { cols: u64, rows: u64 },
    Focus(bool),
    Facts(Value),
}

#[derive(Default)]
struct State {
    terms: HashMap<String, Term>,
    by_block: HashMap<String, String>,
    /// Sessions attached with `session.attach`, which data connections need.
    attached: HashSet<String>,
    seq: u64,
    subscribers: Vec<u32>,
    views: HashMap<u32, View>,
    next_channel: u32,
}

struct Bridge {
    rex: Arc<Control>,
    host_id: String,
    started: Instant,
    state: Mutex<State>,
    mirror: Mutex<mirror::Mirror>,
    /// Tells the mirror Rex's sessions changed.
    kick: Mutex<Option<mpsc::Sender<()>>>,
    out: mpsc::Sender<Vec<u8>>,
    frames: Take<mpsc::Receiver<Vec<u8>>>,
    events: Take<mpsc::Receiver<Value>>,
}

/// A value handed out once, after start.
struct Take<T>(Mutex<Option<T>>);
impl<T> Take<T> {
    fn take(&self) -> Option<T> {
        self.0.lock().unwrap().take()
    }
}

impl Bridge {
    fn start() -> Result<Arc<Bridge>> {
        let socket = socket_path()?;
        let (rex, events) = Control::connect(&socket)?;
        let status = rex.call("server.status", json!({}))?;
        let (out, frames) = mpsc::channel();
        let bridge = Arc::new(Bridge {
            rex,
            host_id: status["host_id"].as_str().unwrap_or_default().to_owned(),
            started: Instant::now(),
            state: Mutex::default(),
            mirror: Mutex::default(),
            kick: Mutex::default(),
            out,
            frames: Take(Mutex::new(Some(frames))),
            events: Take(Mutex::new(Some(events))),
        });
        // Events from now on; the list below is what was there before them.
        let all = bridge.rex.call("session.attach_all", json!({"event_scope": "all"}))?;
        let sessions = all["sessions"].as_array().cloned().unwrap_or_default();
        for session in &sessions {
            let id = session["session_id"].as_str().unwrap_or_default();
            let blocks = bridge.rex.call("session.list_blocks", json!({"session_id": id}))?;
            for block in blocks["blocks"].as_array().into_iter().flatten() {
                if is_terminal(block)
                    && let Some(block_id) = block["block_id"].as_str()
                {
                    bridge.found(id, block_id);
                }
            }
        }
        let kick = bridge.start_mirror(&sessions)?;
        *bridge.kick.lock().unwrap() = Some(kick);
        Ok(bridge)
    }

    fn hello(&self) -> Value {
        let methods: Vec<&str> = METHODS.to_vec();
        json!({
            "generation": crate::hc::GENERATION,
            "version": crate::hc::core_min(),
            "core": self.core_info(),
            "framed": true,
            "methods": methods,
            "features": ["rex"],
        })
    }

    fn core_info(&self) -> Value {
        let name = std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()).unwrap_or_default();
        json!({"id": self.host_id, "name": name})
    }

    fn send(&self, channel: u32, kind: u8, payload: &[u8]) {
        let _ = self.out.send(crate::hc::encode(channel, kind, payload));
    }

    // ---- requests on channel 0 ----

    fn request(self: &Arc<Self>, payload: &[u8]) {
        let Ok(msg) = serde_json::from_slice::<Value>(payload) else { return };
        let Some(id) = msg.get("id").cloned() else { return };
        let method = msg["method"].as_str().unwrap_or_default();
        let reply = match self.call(method, &msg["params"]) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
        };
        self.send(0, DATA, reply.to_string().as_bytes());
    }

    fn call(self: &Arc<Self>, method: &str, p: &Value) -> Result<Value, Value> {
        let rex = |r: Result<Value>| r.map_err(|e| rex_error(&e));
        match method {
            "hello" => Ok(self.hello()),
            "server.status" => {
                let st = self.state.lock().unwrap();
                let finished = st.terms.values().filter(|t| t.record["state"] == "finished").count();
                Ok(json!({
                    "core": self.core_info(),
                    "version": crate::hc::core_min(),
                    "pid": std::process::id(),
                    "uptime_ms": self.started.elapsed().as_millis() as u64,
                    "holders": [],
                    "live": st.terms.len() - finished,
                    "finished": finished,
                    "installed_by": "rex",
                }))
            }
            "machine.list" => Ok(json!({"machines": []})),
            "terminal.list" => {
                let all = p["all"].as_bool().unwrap_or(false);
                let want = p["labels"].as_object().cloned().unwrap_or_default();
                let st = self.state.lock().unwrap();
                let terminals: Vec<Value> = sorted(&st)
                    .into_iter()
                    .filter(|t| all || t.record["state"] == "live")
                    .filter(|t| want.iter().all(|(k, v)| &t.record["labels"][k] == v))
                    .map(|t| t.record.clone())
                    .collect();
                Ok(json!({"terminals": terminals, "hidden_finished": 0, "machines": []}))
            }
            "terminal.get" => self.with_term(p, |t| t.record.clone()),
            "terminal.run" => self.run(p),
            "terminal.attach" => self.attach(p),
            "terminal.kill" => {
                let (session, block, mut record) = self.with_term(p, |t| (t.session.clone(), t.block.clone(), t.record.clone()))?;
                rex(self.rex.call("block.close", json!({"session_id": session, "block_id": block})))?;
                let mut st = self.state.lock().unwrap();
                if let Some(address) = st.by_block.get(&block).cloned() {
                    self.finish(&mut st, &address, "killed", None);
                    return Ok(st.terms[&address].record.clone());
                }
                // Rex's block_closed got here first.
                record["state"] = json!("finished");
                record["reason"] = json!("killed");
                Ok(record)
            }
            "terminal.label" => {
                let changes = p["labels"].as_object().cloned().unwrap_or_default();
                let block = self.with_term(p, |t| t.block.clone())?;
                let known = store::update(&block, |k| {
                    for (key, value) in &changes {
                        match value.as_str().unwrap_or_default() {
                            "" => k.labels.remove(key),
                            v => k.labels.insert(key.clone(), v.to_owned()),
                        };
                    }
                })
                .map_err(|e| rpc_error("internal", &format!("{e:#}")))?;
                self.changed(&block, |t| t.record["labels"] = json!(known.labels), "labels", |t| json!({"labels": t.record["labels"]}))
            }
            "terminal.keep" => {
                let keep = p["keep"].as_bool().unwrap_or(false);
                let block = self.with_term(p, |t| t.block.clone())?;
                store::update(&block, |k| k.keep = keep).map_err(|e| rpc_error("internal", &format!("{e:#}")))?;
                self.changed(&block, |t| t.record["keep"] = json!(keep), "keep", |_| json!({"keep": keep}))
            }
            "terminal.read" => {
                let (session, block, rows) = self.with_term(p, |t| (t.session.clone(), t.block.clone(), t.record["rows"].as_u64().unwrap_or(24)))?;
                let lines = p["lines"].as_u64().unwrap_or(0);
                let shown = rex(self.rex.block_call(&session, &block, "com.superlogical.terminal.format", json!({"format": "text", "trim": true})))?;
                let text = shown["content"].as_str().unwrap_or_default();
                let all: Vec<&str> = text.lines().collect();
                let keep = (rows + lines) as usize;
                let text = all[all.len().saturating_sub(keep)..].join("\n");
                Ok(json!({"text": text, "complete": true, "how": "screen", "why": null}))
            }
            "terminal.send" | "terminal.interrupt" => {
                let (session, block) = self.with_term(p, |t| (t.session.clone(), t.block.clone()))?;
                let data = if method == "terminal.interrupt" { "\x03".to_owned() } else { p["text"].as_str().unwrap_or_default().to_owned() };
                rex(self.rex.block_call(&session, &block, "com.superlogical.terminal.write", json!({"data": data})))?;
                self.with_term(p, |t| t.record.clone())
            }
            "doc.get" if p["name"] == mirror::DOC => {
                local_only(p)?;
                Ok(self.doc_get())
            }
            "doc.set" if p["name"] == mirror::DOC => {
                local_only(p)?;
                match self.doc_set(&p["value"], p["version"].as_u64().unwrap_or(0)).map_err(|e| rex_error(&e))? {
                    Ok(version) => Ok(json!({"version": version})),
                    Err(current) => Err(rpc_error("conflict", &format!("{} is at version {current}", mirror::DOC))),
                }
            }
            "doc.get" => {
                local_only(p)?;
                let doc = store::doc_get(p["name"].as_str().unwrap_or_default()).map_err(|e| rpc_error("internal", &format!("{e:#}")))?;
                Ok(json!({"value": doc.value, "version": doc.version}))
            }
            "doc.set" => {
                local_only(p)?;
                let name = p["name"].as_str().unwrap_or_default();
                let version = p["version"].as_u64().unwrap_or(0);
                match store::doc_set(name, p["value"].clone(), version).map_err(|e| rpc_error("internal", &format!("{e:#}")))? {
                    Ok(version) => {
                        let mut st = self.state.lock().unwrap();
                        st.seq += 1;
                        let line = json!({"jsonrpc": "2.0", "method": "event", "params": {"seq": st.seq, "type": "doc", "data": {"name": name, "version": version}}});
                        self.broadcast(&st, &line);
                        Ok(json!({"version": version}))
                    }
                    Err(current) => Err(rpc_error("conflict", &format!("{name} is at version {current}"))),
                }
            }
            "events.subscribe" => {
                let mut st = self.state.lock().unwrap();
                st.next_channel += 1;
                let channel = st.next_channel;
                st.subscribers.push(channel);
                let terminals: Vec<Value> = sorted(&st).into_iter().map(|t| t.record.clone()).collect();
                Ok(json!({"seq": st.seq, "terminals": terminals, "channel": channel}))
            }
            other => Err(json!({"code": -32601, "message": format!("{other} isn't available with the Rex backend"), "data": {"kind": "unsupported"}})),
        }
    }

    fn with_term<R>(&self, p: &Value, f: impl FnOnce(&Term) -> R) -> Result<R, Value> {
        let address = p["terminal"].as_str().unwrap_or_default();
        let st = self.state.lock().unwrap();
        let t = st
            .terms
            .get(address)
            .or_else(|| st.terms.values().find(|t| t.record["name"].as_str() == Some(address)))
            .ok_or_else(|| rpc_error("not_found", &format!("no terminal {address}")))?;
        Ok(f(t))
    }

    /// Applies a change to the block's record and tells the subscribers.
    fn changed(&self, block: &str, apply: impl FnOnce(&mut Term), kind: &str, data: impl FnOnce(&Term) -> Value) -> Result<Value, Value> {
        let mut st = self.state.lock().unwrap();
        let address = st.by_block.get(block).cloned().ok_or_else(|| rpc_error("not_found", "that terminal is gone"))?;
        let t = st.terms.get_mut(&address).unwrap();
        apply(t);
        let (data, record) = (data(t), t.record.clone());
        self.emit(&mut st, kind, &address, data);
        Ok(record)
    }

    fn run(self: &Arc<Self>, p: &Value) -> Result<Value, Value> {
        if p["on"].as_str().is_some_and(|m| !m.is_empty()) {
            return Err(rpc_error("unsupported", "other machines aren't supported with the Rex backend yet"));
        }
        let mut argv: Vec<String> = p["argv"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_owned)).collect();
        if let Some(line) = p["line"].as_str() {
            argv = vec!["/bin/sh".into(), "-c".into(), line.to_owned()];
        }
        let cwd = p["cwd"].as_str().unwrap_or_default().to_owned();
        // A terminal for a space starts in its session; the app's next layout write places it.
        let session = match p["labels"]["herdr.space"].as_str().filter(|s| !s.is_empty()) {
            Some(space) => self.space_session(space),
            None => self.parking(),
        }
        .map_err(|e| rex_error(&e))?;
        let label = p["name"].as_str().map(str::to_owned).or_else(|| argv.first().map(|a| a.rsplit('/').next().unwrap_or(a).to_owned()));
        let mut payload = json!({
            "session_id": session,
            "flavor": SHELL,
            "options": {"command": if argv.is_empty() { Value::Null } else { json!(argv) }, "cwd": cwd},
        });
        if let Some(label) = label.filter(|l| !l.is_empty()) {
            payload["label"] = json!(label.chars().take(128).collect::<String>());
        }
        let made = self.rex.call("session.new_block", payload).map_err(|e| rex_error(&e))?;
        let block = made["block_id"].as_str().ok_or_else(|| rpc_error("internal", "Rex made no block"))?.to_owned();
        let labels: BTreeMap<String, String> = p["labels"].as_object().into_iter().flatten().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned()))).filter(|(_, v)| !v.is_empty()).collect();
        let keep = p["keep"].as_bool().unwrap_or(false);
        store::known(&block).map_err(|e| rpc_error("internal", &format!("{e:#}")))?;
        let known = store::update(&block, |k| {
            k.labels = labels;
            k.keep = keep;
        })
        .map_err(|e| rpc_error("internal", &format!("{e:#}")))?;
        let mut record = new_record(&known, &block);
        record["argv"] = json!(argv);
        record["cwd"] = json!(cwd);
        record["name"] = p["name"].clone();
        let mut st = self.state.lock().unwrap();
        // The block_created event may have found it first.
        if let Some(address) = st.by_block.get(&block) {
            return Ok(st.terms[address].record.clone());
        }
        self.add(&mut st, &session, &block, record.clone(), BTreeMap::new());
        Ok(record)
    }

    // ---- terminals ----

    /// A terminal block that was already there, or one Rex just announced.
    fn found(&self, session: &str, block: &str) {
        if self.state.lock().unwrap().by_block.contains_key(block) {
            return;
        }
        let Ok(known) = store::known(block) else { return };
        let call = |method: &str| self.rex.block_call(session, block, &format!("{TERMINAL}.{method}"), json!({})).unwrap_or(Value::Null);
        let mut record = new_record(&known, block);
        record["title"] = json!(call("title")["title"].as_str().unwrap_or_default());
        let process = call("process");
        // A block still starting reports neither, and an empty folder would
        // spread to its space and the mods that run programs there: Rex's home
        // is the folder such a shell starts in.
        record["cwd"] = json!(process_cwd(&process));
        record["pid"] = if process["child"]["pid"].is_null() { process["foreground"]["pid"].clone() } else { process["child"]["pid"].clone() };
        record["foreground"] = foreground(&process["foreground"]);
        if let Some(code) = process["last_exit"]["exit_code"].as_i64() {
            record["state"] = json!("finished");
            record["reason"] = json!("exited");
            record["exit_code"] = json!(code);
            record["finished_ms"] = json!(now_ms());
            record["foreground"] = Value::Null;
        }
        let size = call("size");
        if let (Some(cols), Some(rows)) = (size["columns"].as_u64(), size["rows"].as_u64()) {
            record["cols"] = json!(cols);
            record["rows"] = json!(rows);
        }
        let status: BTreeMap<String, Value> = call("program_status")["records"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| (r["id"].as_str().unwrap_or_default().to_owned(), r.clone()))
            .collect();
        let mut st = self.state.lock().unwrap();
        if st.by_block.contains_key(block) {
            return;
        }
        self.add(&mut st, session, block, record, status);
    }

    fn add(&self, st: &mut State, session: &str, block: &str, record: Value, status: BTreeMap<String, Value>) {
        let address = record["address"].as_str().unwrap_or_default().to_owned();
        let mut term = Term { session: session.to_owned(), block: block.to_owned(), record, status };
        if !term.status.is_empty() {
            apply_status(&mut term);
        }
        let record = term.record.clone();
        st.by_block.insert(block.to_owned(), address.clone());
        st.terms.insert(address.clone(), term);
        self.emit(st, "created", &address, record);
    }

    fn finish(&self, st: &mut State, address: &str, reason: &str, exit_code: Option<i64>) {
        let Some(t) = st.terms.get_mut(address) else { return };
        if t.record["state"] == "finished" {
            return;
        }
        let had_status = !t.record["status"].is_null();
        t.status.clear();
        let finished_ms = now_ms();
        t.record["state"] = json!("finished");
        t.record["reason"] = json!(reason);
        t.record["exit_code"] = json!(exit_code);
        t.record["signal"] = Value::Null;
        t.record["finished_ms"] = json!(finished_ms);
        t.record["foreground"] = Value::Null;
        t.record["status"] = Value::Null;
        let records = t.record["records"].clone();
        if had_status {
            self.emit(st, "status", address, json!({"status": null, "records": records, "reported": true}));
        }
        self.emit(st, "finished", address, json!({"reason": reason, "exit_code": exit_code, "signal": null, "finished_ms": finished_ms}));
    }

    fn remove(&self, st: &mut State, address: &str) {
        let Some(t) = st.terms.remove(address) else { return };
        st.by_block.remove(&t.block);
        let _ = store::forget(&t.block);
        self.emit(st, "removed", address, json!({}));
    }

    fn doc_changed(&self, version: u64) {
        let mut st = self.state.lock().unwrap();
        st.seq += 1;
        let line = json!({"jsonrpc": "2.0", "method": "event", "params": {"seq": st.seq, "type": "doc", "data": {"name": mirror::DOC, "version": version}}});
        self.broadcast(&st, &line);
    }

    fn emit(&self, st: &mut State, kind: &str, address: &str, data: Value) {
        st.seq += 1;
        let line = json!({"jsonrpc": "2.0", "method": "event", "params": {"seq": st.seq, "type": kind, "terminal": address, "data": data}});
        self.broadcast(st, &line);
    }

    fn broadcast(&self, st: &State, line: &Value) {
        let mut bytes = line.to_string().into_bytes();
        bytes.push(b'\n');
        for channel in &st.subscribers {
            self.send(*channel, DATA, &bytes);
        }
    }

    // ---- Rex events ----

    fn on_event(&self, event: &Value) {
        let p = &event["payload"];
        match event["type"].as_str() {
            Some("session_created" | "session_moved") => self.kick_mirror(),
            Some("session_destroyed") => {
                let session = p["session_id"].as_str().unwrap_or_default();
                let mut st = self.state.lock().unwrap();
                st.attached.remove(session);
                let gone: Vec<String> = st.terms.iter().filter(|(_, t)| t.session == session).map(|(a, _)| a.clone()).collect();
                for address in gone {
                    self.finish(&mut st, &address, "exited", None);
                    self.remove(&mut st, &address);
                }
                drop(st);
                self.kick_mirror();
            }
            Some("session_event") => {
                let session = p["session_id"].as_str().unwrap_or_default();
                let inner = &p["event"]["payload"];
                let block = inner["block_id"].as_str().unwrap_or_default();
                match p["event"]["type"].as_str() {
                    Some("block_created") => {
                        let described = self.rex.call("session.describe_block", json!({"session_id": session, "block_id": block}));
                        if described.is_ok_and(|d| is_terminal(&d["block"])) {
                            self.found(session, block);
                        }
                    }
                    Some("block_closed") => {
                        let mut st = self.state.lock().unwrap();
                        if let Some(address) = st.by_block.get(block).cloned() {
                            self.finish(&mut st, &address, "exited", None);
                            self.remove(&mut st, &address);
                        }
                    }
                    Some("block_event") if inner["creator_name"] == TERMINAL => self.block_event(block, inner["name"].as_str().unwrap_or_default(), &inner["payload"]),
                    _ => {}
                }
                // Windows, layouts and labels: the mirror looks again.
                if p["event"]["type"] != "block_event" {
                    self.kick_mirror();
                }
            }
            _ => {}
        }
    }

    fn block_event(&self, block: &str, name: &str, p: &Value) {
        let mut st = self.state.lock().unwrap();
        let Some(address) = st.by_block.get(block).cloned() else { return };
        let t = st.terms.get_mut(&address).unwrap();
        match name {
            "title_changed" => {
                let title = p["title"].as_str().unwrap_or_default();
                if t.record["title"] == title {
                    return;
                }
                t.record["title"] = json!(title);
                self.emit(&mut st, "title", &address, json!({"title": title}));
            }
            "process_changed" => {
                if t.record["state"] == "finished" {
                    return;
                }
                let fg = foreground(&p["foreground"]);
                t.record["foreground"] = fg.clone();
                self.emit(&mut st, "foreground", &address, fg);
            }
            "size_changed" => {
                let cols = p["columns"].as_u64().or(p["cols"].as_u64());
                let (Some(cols), Some(rows)) = (cols, p["rows"].as_u64()) else { return };
                t.record["cols"] = json!(cols);
                t.record["rows"] = json!(rows);
                self.emit(&mut st, "size", &address, json!({"cols": cols, "rows": rows}));
            }
            "program_status_changed" | "program_status_removed" => {
                if name == "program_status_changed" {
                    t.status.insert(p["id"].as_str().unwrap_or_default().to_owned(), p["record"].clone());
                } else {
                    for id in p["ids"].as_array().into_iter().flatten() {
                        t.status.remove(id.as_str().unwrap_or_default());
                    }
                }
                let before = t.record["status"]["state"].as_str().map(str::to_owned);
                apply_status(t);
                let after = t.record["status"]["state"].as_str().map(str::to_owned);
                let data = json!({"status": t.record["status"], "records": t.record["records"], "reported": true});
                let turn = (before.as_deref() == Some("working") && after.as_deref() != Some("working")).then(|| {
                    let turn = t.record["turn"].as_u64().unwrap_or(0) + 1;
                    t.record["turn"] = json!(turn);
                    json!({"turn": turn, "state": after.unwrap_or_else(|| "idle".into())})
                });
                self.emit(&mut st, "status", &address, data);
                if let Some(turn) = turn {
                    self.emit(&mut st, "turn", &address, turn);
                }
            }
            "child_exited" => self.finish(&mut st, &address, "exited", p["exit_code"].as_i64()),
            _ => {}
        }
    }

    // ---- attach streams ----

    fn attach(self: &Arc<Self>, p: &Value) -> Result<Value, Value> {
        let (session, block, record) = self.with_term(p, |t| (t.session.clone(), t.block.clone(), t.record.clone()))?;
        if record["state"] == "finished" {
            return Err(rpc_error("finished", &format!("{} has finished", record["address"].as_str().unwrap_or_default())));
        }
        self.attach_session(&session).map_err(|e| rex_error(&e))?;
        let (reader, writer, welcome) = self.open_data(&session, &block).map_err(|e| rpc_error("unavailable", &format!("{e:#}")))?;
        let observe = p["observe"].as_bool().unwrap_or(false);
        let history = p["history"].as_u64().unwrap_or(0) as usize;
        let (ops, ops_rx) = mpsc::channel();
        let data = Arc::new(Mutex::new(Some(writer)));
        let channel = {
            let mut st = self.state.lock().unwrap();
            st.next_channel += 1;
            let channel = st.next_channel;
            st.views.insert(channel, View { ops: ops.clone(), data: data.clone() });
            channel
        };
        if !observe {
            let _ = ops.send(Op::Facts(p["display"].clone()));
            // As with herdr-core, the viewer that attaches sets the size: the
            // app draws the terminal at its pane's size, whoever else shows it.
            if let (Some(cols), Some(rows)) = (p["cols"].as_u64(), p["rows"].as_u64()) {
                let _ = ops.send(Op::Size { cols, rows });
            }
        }
        let b = self.clone();
        let (s, k) = (session.clone(), block.clone());
        std::thread::Builder::new().name("rex-ops".into()).spawn(move || b.ops(&s, &k, ops_rx, observe)).map_err(|e| rpc_error("internal", &e.to_string()))?;
        let b = self.clone();
        std::thread::Builder::new()
            .name("rex-stream".into())
            .spawn(move || b.pump(channel, &session, &block, reader, welcome, data, history))
            .map_err(|e| rpc_error("internal", &e.to_string()))?;
        Ok(json!({"channel": channel, "terminal": record}))
    }

    fn attach_session(&self, session: &str) -> Result<()> {
        if self.state.lock().unwrap().attached.contains(session) {
            return Ok(());
        }
        match self.rex.call("session.attach", json!({"session_id": session})) {
            Ok(_) => {}
            // Attached already (another attach got there first).
            Err(e) if control::error_code(&e) == Some("conflict") => {}
            Err(e) => return Err(e),
        }
        self.state.lock().unwrap().attached.insert(session.to_owned());
        Ok(())
    }

    fn open_data(&self, session: &str, block: &str) -> Result<(ws::Reader, ws::Writer, Welcome)> {
        let ticket = self.rex.call("data.connect", json!({"session_id": session, "block_id": block, "data_ref_id": "terminal", "subprotocol": DATA_PROTOCOL}))?;
        let ticket = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(ticket["ticket"].as_str().unwrap_or_default()).context("bad data ticket")?;
        let (mut reader, writer) = ws::connect(&self.rex.socket, "/api/data", DATA_PROTOCOL)?;
        let mut hello = vec![0x01];
        hello.extend(ticket);
        writer.binary(&hello)?;
        let welcome = Welcome::read(&mut reader)?;
        Ok((reader, writer, welcome))
    }

    /// Continues a dropped stream from the bytes already used.
    fn resume(&self, welcome: &Welcome, received: u64) -> Result<(ws::Reader, ws::Writer, Welcome)> {
        let (mut reader, writer) = ws::connect(&self.rex.socket, "/api/data", DATA_PROTOCOL)?;
        let mut resume = vec![0x02];
        resume.extend(welcome.token);
        resume.extend(received.to_le_bytes());
        writer.binary(&resume)?;
        let welcome = Welcome::read(&mut reader)?;
        Ok((reader, writer, welcome))
    }

    /// Relays one block's stream to the app's channel.
    #[allow(clippy::too_many_arguments)]
    fn pump(&self, channel: u32, session: &str, block: &str, mut reader: ws::Reader, mut welcome: Welcome, data: Arc<Mutex<Option<ws::Writer>>>, history: usize) {
        let mut filter = stream::Filter::new(welcome.nonce);
        let (mut snapshot, mut painted, mut received) = (Vec::new(), false, 0u64);
        let mut failures = 0u64;
        loop {
            let message = reader.read();
            let open = self.state.lock().unwrap().views.contains_key(&channel);
            if !open {
                return;
            }
            let why = match message {
                Ok(ws::Message::Binary(bytes)) => {
                    received += bytes.len() as u64;
                    failures = 0;
                    for piece in filter.push(&bytes) {
                        match piece {
                            stream::Piece::Snapshot(b) => snapshot.extend(b),
                            stream::Piece::Output(b) => self.send(channel, DATA, &b),
                            stream::Piece::Message(m) => {
                                if !painted {
                                    painted = true;
                                    let paint = snapshot::to_vt(&snapshot, history).unwrap_or_else(|| {
                                        eprintln!("herdr-app rex-core: can't read Rex's snapshot of {block} ({} bytes); Rex paints it instead", snapshot.len());
                                        self.server_paint(session, block)
                                    });
                                    snapshot = Vec::new();
                                    self.send(channel, DATA, &paint);
                                }
                                if m["type"] == "child_exited" {
                                    let exit = json!({"reason": "exited", "exit_code": m["exit_code"], "signal": null});
                                    return self.end(channel, &exit);
                                }
                            }
                        }
                    }
                    continue;
                }
                Ok(ws::Message::Text(_)) => continue,
                Ok(ws::Message::Close(code, reason)) => format!("{code} {reason}"),
                Err(e) => format!("{e:#}"),
            };
            if why.starts_with("4000") || !self.state.lock().unwrap().by_block.contains_key(block) {
                return self.end(channel, &json!({"reason": "exited", "exit_code": null, "signal": null}));
            }
            failures += 1;
            if failures > 5 {
                tracing::warn!("rex stream for {block} lost: {why}");
                return self.end(channel, &json!({"reason": "lost", "exit_code": null, "signal": null}));
            }
            std::thread::sleep(Duration::from_millis(200 * failures));
            let reopened = match self.resume(&welcome, received) {
                Ok(r) => Ok(r),
                // Start over: a new stream repaints the whole terminal.
                Err(_) => self.open_data(session, block).map(|r| {
                    filter = stream::Filter::new(r.2.nonce);
                    (snapshot, painted, received) = (Vec::new(), false, 0);
                    self.send(channel, DATA, b"\x1bc");
                    r
                }),
            };
            if let Ok((r, w, wl)) = reopened {
                reader = r;
                welcome = wl;
                *data.lock().unwrap() = Some(w);
            }
        }
    }

    /// The screen as Rex paints it, when this Ghostty can't read Rex's snapshot.
    fn server_paint(&self, session: &str, block: &str) -> Vec<u8> {
        let mut args = json!({"format": "vt"});
        for extra in ["charsets", "cursor", "hyperlink", "keyboard", "kitty_keyboard", "modes", "palette", "protection", "pwd", "scrolling_region", "style", "tabstops"] {
            args[format!("extra_{extra}")] = json!(true);
        }
        match self.rex.block_call(session, block, &format!("{TERMINAL}.format"), args) {
            Ok(v) => v["content"].as_str().unwrap_or_default().as_bytes().to_vec(),
            Err(e) => {
                tracing::warn!("cannot paint {block}: {e:#}");
                Vec::new()
            }
        }
    }

    fn end(&self, channel: u32, why: &Value) {
        if let Some(view) = self.state.lock().unwrap().views.remove(&channel)
            && let Some(w) = view.data.lock().unwrap().take()
        {
            w.close(1000);
        }
        self.send(channel, CLOSE, why.to_string().as_bytes());
    }

    /// What the app sends on an attach channel.
    fn stream_frame(&self, channel: u32, kind: u8, payload: Vec<u8>) {
        let mut st = self.state.lock().unwrap();
        if kind == CLOSE {
            if let Some(view) = st.views.remove(&channel)
                && let Some(w) = view.data.lock().unwrap().take()
            {
                w.close(1000);
            }
            st.subscribers.retain(|c| *c != channel);
            drop(st);
            self.send(channel, CLOSE, &[]);
            return;
        }
        let Some(view) = st.views.get(&channel) else { return };
        let op = match kind {
            DATA => Op::Input(payload),
            RESIZE if payload.len() >= 4 => Op::Size {
                cols: u16::from_le_bytes([payload[0], payload[1]]) as u64,
                rows: u16::from_le_bytes([payload[2], payload[3]]) as u64,
            },
            FOCUS => Op::Focus(payload.first() == Some(&1)),
            FACTS => Op::Facts(serde_json::from_slice(&payload).unwrap_or(Value::Null)),
            // Rex's WebSockets carry their own flow control.
            CREDIT => return,
            _ => return,
        };
        let _ = view.ops.send(op);
    }

    /// Typing, size and colors for one attach, in the order the app sent them.
    /// Rex sizes a block for its owner, so the app takes the block whenever
    /// herdr-core would make it the active viewer: on attach, resize, focus
    /// and typing (Rex.app may have taken it since).
    fn ops(&self, session: &str, block: &str, rx: mpsc::Receiver<Op>, observe: bool) {
        let block_call = |method: &str, args: Value| {
            if let Err(e) = self.rex.block_call(session, block, &format!("{TERMINAL}.{method}"), args) {
                tracing::debug!("{method} on {block}: {e:#}");
            }
        };
        let own = || {
            let _ = self.rex.call("session.own_block", json!({"session_id": session, "block_ids": [block], "mode": "take"}));
        };
        let mut cell: Option<(u64, u64)> = None;
        // When typing last took the block: a burst of keys takes it once.
        let mut owned_at: Option<Instant> = None;
        while let Ok(first) = rx.recv() {
            let mut batch = vec![first];
            batch.extend(rx.try_iter());
            let mut typed: Vec<u8> = Vec::new();
            let flush = |typed: &mut Vec<u8>, owned_at: &mut Option<Instant>| {
                if typed.is_empty() {
                    return;
                }
                if owned_at.is_none_or(|at| at.elapsed() > Duration::from_millis(500)) {
                    own();
                    *owned_at = Some(Instant::now());
                }
                block_call("write", json!({"data": String::from_utf8_lossy(typed)}));
                typed.clear();
            };
            for op in batch {
                if observe {
                    continue;
                }
                match op {
                    Op::Input(bytes) => typed.extend(bytes),
                    Op::Size { cols, rows } => {
                        flush(&mut typed, &mut owned_at);
                        own();
                        owned_at = Some(Instant::now());
                        let mut args = json!({"columns": cols, "rows": rows});
                        if let Some((w, h)) = cell {
                            args["cell_width_px"] = json!(w);
                            args["cell_height_px"] = json!(h);
                        }
                        block_call("resize", args);
                    }
                    Op::Focus(focused) => {
                        flush(&mut typed, &mut owned_at);
                        if focused {
                            own();
                            owned_at = Some(Instant::now());
                        }
                        let _ = self.rex.call("block.event", json!({"session_id": session, "block_id": block, "event": {"type": "focus", "payload": {"focused": focused}}}));
                    }
                    Op::Facts(display) => {
                        if let Some([w, h]) = display["cell"].as_array().map(|c| [c.first().and_then(Value::as_u64), c.get(1).and_then(Value::as_u64)]) {
                            cell = w.zip(h);
                        }
                        let mut theme = json!({});
                        for (from, to) in [("fg", "foreground"), ("bg", "background"), ("cursor", "cursor")] {
                            if let Some(c) = display[from].as_str() {
                                theme[to] = json!(c);
                            }
                        }
                        block_call("set_theme", theme);
                    }
                }
            }
            flush(&mut typed, &mut owned_at);
        }
    }
}

struct Welcome {
    token: [u8; 16],
    nonce: u64,
}

impl Welcome {
    /// WELCOME: 0x81, a 16-byte token, 3 zero bytes, a u32 grace, a u64 nonce. REJECT: 0x82, a reason.
    fn read(reader: &mut ws::Reader) -> Result<Welcome> {
        match reader.read()? {
            ws::Message::Binary(b) if b.len() == 32 && b[0] == 0x81 => Ok(Welcome {
                token: b[1..17].try_into().unwrap(),
                nonce: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            }),
            ws::Message::Binary(b) if b.first() == Some(&0x82) => bail!("Rex refused the terminal stream (reason {:#04x})", b.get(1).copied().unwrap_or(0)),
            ws::Message::Close(code, reason) => bail!("Rex closed the terminal stream ({code} {reason})"),
            _ => bail!("unexpected Rex data handshake"),
        }
    }
}

fn local_only(p: &Value) -> Result<(), Value> {
    match p["on"].as_str() {
        Some(m) if !m.is_empty() => Err(rpc_error("unavailable", "other machines aren't supported with the Rex backend yet")),
        _ => Ok(()),
    }
}

/// Terminals in address order (`t2` before `t10`).
fn sorted(st: &State) -> Vec<&Term> {
    let mut terms: Vec<&Term> = st.terms.values().collect();
    terms.sort_by_key(|t| t.record["address"].as_str().and_then(|a| a.trim_start_matches('t').parse::<u64>().ok()).unwrap_or(u64::MAX));
    terms
}

fn new_record(known: &store::Known, block: &str) -> Value {
    json!({
        "address": known.address,
        "labels": known.labels,
        "keep": known.keep,
        "argv": [],
        "cwd": "",
        "state": "live",
        "created_ms": id_ms(block).unwrap_or_else(now_ms),
        "screen": "exact",
        "cols": 80,
        "rows": 24,
        "title": "",
        "name": null,
        "pid": null,
        "foreground": null,
        "status": null,
        "status_ms": null,
        "records": {},
        "reported": false,
        "turn": 0,
        "reason": null,
        "exit_code": null,
        "signal": null,
        "finished_ms": null,
        "identity": "rex",
        "rex": {"block_id": block},
    })
}

/// A Rex block that is a herdr terminal: a terminal block, but not the
/// placeholder that holds a new window open (mirror.rs).
fn is_terminal(block: &Value) -> bool {
    block["creator_name"] == TERMINAL && block["label"] != mirror::PLACEHOLDER
}

/// Rex's description of a process, as herdr's `foreground`.
fn foreground(fg: &Value) -> Value {
    if fg.is_null() {
        return Value::Null;
    }
    let script = fg["script"].as_str().and_then(|s| s.rsplit('/').next());
    let name = script.or(fg["name"].as_str()).unwrap_or_default();
    json!({
        "pid": fg["pid"],
        "name": name,
        "argv": [fg["argv0"].as_str().unwrap_or(name)],
        "cwd": fg["cwd"].as_str().unwrap_or_default(),
    })
}

/// A block's folder: what runs there, else where Rex says its home is.
fn process_cwd(process: &Value) -> &str {
    process["child"]["cwd"]
        .as_str()
        .or(process["foreground"]["cwd"].as_str())
        .or(process["home"].as_str())
        .unwrap_or_default()
}

/// Rex program status records (OSC 7501, as herdr's) into the record's
/// `status` (the root record) and `records` (the rest).
fn apply_status(t: &mut Term) {
    let convert = |r: &Value| {
        json!({
            "state": r["state"].as_str().unwrap_or("idle"),
            "kind": r["kind"],
            "msg": r["msg"].as_str().unwrap_or_default(),
            "title": r["title"].as_str().unwrap_or_default(),
            "app": r["effective_app"].as_str().or(r["app"].as_str()).unwrap_or_default(),
            "progress": r["progress"],
        })
    };
    let root = t.status.get("").map(convert).unwrap_or(Value::Null);
    let records: serde_json::Map<String, Value> = t.status.iter().filter(|(id, _)| !id.is_empty()).map(|(id, r)| (id.clone(), convert(r))).collect();
    if t.record["status"]["state"] != root["state"] {
        t.record["status_ms"] = json!(now_ms());
    }
    t.record["status"] = root;
    t.record["records"] = Value::Object(records);
    t.record["reported"] = json!(true);
}

/// The Rex server's Unix socket: `REX_SERVER`, or what the `rex` CLI reports
/// (it knows each platform's default and starts a stopped server).
fn socket_path() -> Result<PathBuf> {
    if let Some(endpoint) = std::env::var("REX_SERVER").ok().filter(|s| !s.is_empty()) {
        return unix_endpoint(&endpoint);
    }
    let mut tried = Vec::new();
    for bin in rex_candidates() {
        let Ok(out) = crate::spawn::command(&bin).args(["whoami", "--json"]).stdin(std::process::Stdio::null()).output() else { continue };
        tried.push(bin.display().to_string());
        if let Ok(who) = serde_json::from_slice::<Value>(&out.stdout)
            && let Some(endpoint) = who["endpoint"].as_str()
        {
            return unix_endpoint(endpoint);
        }
    }
    bail!("no running Rex server found (tried {}); set REX_SERVER=unix:///path/to/server.sock", if tried.is_empty() { "no rex CLI".into() } else { tried.join(", ") })
}

fn rex_candidates() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::env::var_os("REX_BIN_DIR").map(|d| PathBuf::from(d).join("rex")).into_iter().collect();
    found.extend(std::env::var_os("PATH").into_iter().flat_map(|p| std::env::split_paths(&p).map(|d| d.join("rex")).collect::<Vec<_>>()));
    // Rex for Mac keeps its CLI inside the server it installs.
    found.push(crate::mods::home().join("Library/Application Support/com.superlogical.rex/RexServer/Versions/Current/Rex Server.app/Contents/MacOS/rex"));
    found.retain(|p| p.is_file());
    found
}

/// `unix:///path%20with%20spaces/server.sock` as a path.
fn unix_endpoint(endpoint: &str) -> Result<PathBuf> {
    let path = endpoint.strip_prefix("unix://").ok_or_else(|| anyhow!("only local Rex servers (unix://) are supported, not {endpoint}"))?;
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(byte) = path.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    Ok(PathBuf::from(String::from_utf8(out)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_ids_and_status_read_as_herdr_expects() {
        assert_eq!(unix_endpoint("unix:///Users/a/Library/Application%20Support/rex/server.sock").unwrap(), PathBuf::from("/Users/a/Library/Application Support/rex/server.sock"));
        assert!(unix_endpoint("tcp://studio:7000").is_err());
        assert_eq!(id_ms("block:01a192a9-2c15-7493-835f-0c8b2ed46658"), Some(0x01a192a92c15));

        let known = store::Known { address: "t3".into(), ..Default::default() };
        let mut t = Term { session: "s".into(), block: "b".into(), record: new_record(&known, "block:01a192a9-2c15-7493-835f-0c8b2ed46658"), status: BTreeMap::new() };
        t.status.insert("".into(), json!({"state": "blocked", "kind": "permission", "app": "claude", "updated_at": "x"}));
        t.status.insert("build/test".into(), json!({"state": "working", "effective_app": "cargo", "progress": 40, "updated_at": "x"}));
        apply_status(&mut t);
        assert_eq!(t.record["status"]["state"], "blocked");
        assert_eq!(t.record["status"]["app"], "claude");
        assert_eq!(t.record["records"]["build/test"]["app"], "cargo");
        assert_eq!(t.record["reported"], true);

        let fg = foreground(&json!({"pid": 9, "name": "node", "script": "/usr/lib/node_modules/x/cli.js", "argv0": "node", "cwd": "/src"}));
        assert_eq!(fg, json!({"pid": 9, "name": "cli.js", "argv": ["node"], "cwd": "/src"}));
        assert_eq!(foreground(&Value::Null), Value::Null);
    }

    #[test]
    fn a_block_that_has_not_started_still_has_a_folder() {
        let running = json!({"child": {"cwd": "/work"}, "foreground": {"cwd": "/src"}, "home": "/home/a"});
        assert_eq!(process_cwd(&running), "/work", "the shell's folder, as herdr's record has it");
        assert_eq!(process_cwd(&json!({"foreground": {"cwd": "/src"}, "home": "/home/a"})), "/src");
        // Rex says this before the shell is up: not "", which a space would
        // take as its folder and mods would try to run programs in.
        assert_eq!(process_cwd(&json!({"home": "/home/a"})), "/home/a");
        assert_eq!(process_cwd(&json!({})), "");
    }
}
