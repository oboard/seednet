//! Full-screen TUI for SeedNet.
//!
//! Layout:
//!   ┌─────────────────────────────────────────────────────┐
//!   │  Status  │  SeedNet [seed input]  │  Start/Stop     │
//!   ├──────────────────────────┬──────────────────────────┤
//!   │  Peers (scrollable)      │  Log (scrollable)        │
//!   └──────────────────────────┴──────────────────────────┘
//!
//! Tab cycles focus: Seed → Peers → Log
//! ↑/↓ scrolls focused panel; Enter starts/stops; mouse click on seed/button works too.

use std::{
    io,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_LOG_LINES: usize = 500;

#[derive(Debug, Clone, PartialEq)]
enum Focus {
    Seed,
    Peers,
    Log,
}

#[derive(Debug, Clone, PartialEq)]
enum DaemonState {
    Stopped,
    Starting,
    Running { pid: u32, overlay: String },
    Stopping,
}

struct Peer {
    id_short: String,
    overlay: String,
    overlay_ipv6: String,
    underlay: String,
    hostname: String,
    connection: String, // "direct" or "relay"
    relay_via: String,
    is_local: bool,
}

pub struct App {
    seed_input: String,
    seed_cursor: usize,
    focus: Focus,
    daemon: DaemonState,
    daemon_child: Option<Child>,
    peers: Vec<Peer>,
    peers_list_state: ListState,
    log_lines: Vec<String>,
    log_scroll: usize,
    log_col: usize,
    log_follow: bool,
    state_dir: PathBuf,
    exe_path: PathBuf,
    last_poll: Instant,
    log_file_offset: u64,
}

impl App {
    pub fn new(state_dir: PathBuf, exe_path: PathBuf) -> Self {
        let mut s = Self {
            seed_input: String::new(),
            seed_cursor: 0,
            focus: Focus::Seed,
            daemon: DaemonState::Stopped,
            daemon_child: None,
            peers: Vec::new(),
            peers_list_state: ListState::default(),
            log_lines: Vec::new(),
            log_scroll: 0,
            log_col: 0,
            log_follow: true,
            state_dir,
            exe_path,
            last_poll: Instant::now() - POLL_INTERVAL,
            log_file_offset: 0,
        };
        s.push_log("SeedNet TUI ready. Tab to switch focus, Enter or click Start.");
        s
    }

    fn push_log(&mut self, msg: impl Into<String>) {
        let line = format!("{} {}", chrono_time(), msg.into());
        self.log_lines.push(line);
        if self.log_lines.len() > MAX_LOG_LINES {
            self.log_lines.drain(..self.log_lines.len() - MAX_LOG_LINES);
        }
        if self.log_follow {
            self.log_scroll = self.log_lines.len().saturating_sub(1);
        }
    }

    fn toggle_daemon(&mut self) {
        match &self.daemon {
            DaemonState::Stopped => self.start_daemon(),
            DaemonState::Running { .. } => self.stop_daemon(),
            DaemonState::Starting | DaemonState::Stopping => {}
        }
    }

    fn start_daemon(&mut self) {
        let seed = self.seed_input.trim().to_string();
        if seed.is_empty() {
            self.push_log("ERROR: seed is empty — type a seed phrase first.");
            return;
        }

        #[cfg(unix)]
        if libc_getuid() != 0 {
            self.push_log("ERROR: root required for TUN. Run: sudo seednet");
            return;
        }

        self.push_log(format!("Starting daemon (seed: {})…", obscure(&seed)));
        self.daemon = DaemonState::Starting;

        let pid_path = self.state_dir.join("seednet.pid");
        if let Ok(s) = std::fs::read_to_string(&pid_path)
            && let Ok(pid) = s.trim().parse::<u32>()
        {
            #[cfg(unix)]
            libc_kill(pid, 15);
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = std::fs::remove_file(&pid_path);
        }

        self.log_file_offset = std::fs::metadata(self.state_dir.join("seednet.log"))
            .map(|m| m.len())
            .unwrap_or(0);

        let log_path = self.state_dir.join("seednet.log");
        let log_file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(f) => f,
            Err(e) => {
                self.push_log(format!("ERROR opening log: {e}"));
                self.daemon = DaemonState::Stopped;
                return;
            }
        };
        let log_file2 = match log_file.try_clone() {
            Ok(f) => f,
            Err(e) => {
                self.push_log(format!("ERROR cloning log fd: {e}"));
                self.daemon = DaemonState::Stopped;
                return;
            }
        };

        let mut cmd = Command::new(&self.exe_path);
        cmd.arg("-v")
            .arg("_daemon")
            .arg(&seed)
            .arg("--state-dir")
            .arg(&self.state_dir)
            .stdin(Stdio::null())
            .stdout(log_file)
            .stderr(log_file2);

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            cmd.process_group(0);
        }

        match cmd.spawn() {
            Ok(child) => {
                self.push_log(format!("Daemon spawned (pid {})", child.id()));
                self.daemon_child = Some(child);
            }
            Err(e) => {
                self.push_log(format!("ERROR spawning daemon: {e}"));
                self.daemon = DaemonState::Stopped;
            }
        }
    }

    fn stop_daemon(&mut self) {
        self.push_log("Stopping daemon…");
        self.daemon = DaemonState::Stopping;

        let pid_path = self.state_dir.join("seednet.pid");
        if let Ok(s) = std::fs::read_to_string(&pid_path)
            && let Ok(pid) = s.trim().parse::<u32>()
        {
            #[cfg(unix)]
            libc_kill(pid, 15);
            self.push_log(format!("Sent SIGTERM to pid {pid}"));
        }
        if let Some(mut child) = self.daemon_child.take() {
            let _ = child.kill();
        }
        self.peers.clear();
        self.daemon = DaemonState::Stopped;
        self.push_log("Daemon stopped.");
    }

    fn poll(&mut self) {
        if self.last_poll.elapsed() < POLL_INTERVAL {
            return;
        }
        self.last_poll = Instant::now();

        if let Some(child) = self.daemon_child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.push_log(format!("Daemon exited: {status}"));
                    self.daemon_child = None;
                    self.daemon = DaemonState::Stopped;
                    self.peers.clear();
                    return;
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }

        let pid_path = self.state_dir.join("seednet.pid");
        let pid: Option<u32> = std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|s| s.trim().parse().ok());

        match (&self.daemon, pid) {
            (DaemonState::Starting, Some(pid)) => {
                self.push_log(format!("Daemon running (pid {pid})"));
                self.daemon = DaemonState::Running {
                    pid,
                    overlay: String::new(),
                };
            }
            (DaemonState::Running { .. }, None) => {
                self.push_log("Daemon disappeared.");
                self.daemon = DaemonState::Stopped;
                self.daemon_child = None;
                self.peers.clear();
            }
            (DaemonState::Running { pid, overlay }, Some(p)) if *pid != p => {
                let overlay = overlay.clone();
                self.daemon = DaemonState::Running { pid: p, overlay };
            }
            _ => {}
        }

        if matches!(self.daemon, DaemonState::Running { .. }) {
            self.refresh_peers();
        }

        self.tail_daemon_log();
    }

    fn refresh_peers(&mut self) {
        let peers_path = self.state_dir.join("peers.json");
        let Ok(json_str) = std::fs::read_to_string(&peers_path) else {
            return;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&json_str) else {
            return;
        };

        // Local node entry — always first in the list.
        let local: Option<Peer> = v["local"].as_object().and_then(|p| {
            Some(Peer {
                id_short: p["id_short"].as_str()?.to_string(),
                overlay: p["overlay"].as_str()?.to_string(),
                overlay_ipv6: p["overlay_ipv6"].as_str().unwrap_or("").to_string(),
                underlay: String::new(),
                hostname: p["hostname"].as_str().unwrap_or("").to_string(),
                connection: "direct".to_string(),
                relay_via: String::new(),
                is_local: true,
            })
        });

        // Update header overlay display.
        if let Some(ref l) = local
            && let DaemonState::Running { overlay, .. } = &mut self.daemon
        {
            *overlay = l.overlay.clone();
        }

        let Some(arr) = v["peers"].as_array() else {
            return;
        };
        let remote_peers: Vec<Peer> = arr
            .iter()
            .filter_map(|p| {
                Some(Peer {
                    id_short: p["id_short"].as_str()?.to_string(),
                    overlay: p["overlay"].as_str()?.to_string(),
                    overlay_ipv6: p["overlay_ipv6"].as_str().unwrap_or("").to_string(),
                    underlay: p["underlay"].as_str()?.to_string(),
                    hostname: p["hostname"].as_str().unwrap_or("").to_string(),
                    connection: p["connection"].as_str().unwrap_or("direct").to_string(),
                    relay_via: p["relay_via"].as_str().unwrap_or("").to_string(),
                    is_local: false,
                })
            })
            .collect();

        // Count only remote peers for connect/disconnect log messages.
        let old_remote = self.peers.iter().filter(|p| !p.is_local).count();
        let new_remote = remote_peers.len();
        if new_remote > old_remote {
            for p in &remote_peers[old_remote..] {
                self.push_log(format!(
                    "Peer connected: {} ({} / {})",
                    p.id_short, p.overlay, p.underlay
                ));
            }
        } else if new_remote < old_remote {
            self.push_log(format!(
                "{} peer(s) disconnected ({} → {})",
                old_remote - new_remote,
                old_remote,
                new_remote
            ));
        }

        let mut new_peers = Vec::with_capacity(1 + remote_peers.len());
        if let Some(l) = local {
            new_peers.push(l);
        }
        new_peers.extend(remote_peers);
        self.peers = new_peers;
    }

    fn tail_daemon_log(&mut self) {
        let log_path = self.state_dir.join("seednet.log");
        let Ok(meta) = std::fs::metadata(&log_path) else {
            return;
        };
        let file_len = meta.len();
        if file_len <= self.log_file_offset {
            return;
        }

        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut f) = std::fs::File::open(&log_path) else {
            return;
        };
        if f.seek(SeekFrom::Start(self.log_file_offset)).is_err() {
            return;
        }
        let mut raw = Vec::new();
        let _ = f.read_to_end(&mut raw);
        self.log_file_offset = file_len;

        let text = String::from_utf8_lossy(&raw);
        let stripped = strip_ansi(&text);
        for line in stripped.lines() {
            let line = line.trim();
            if !line.is_empty() {
                self.push_log(line);
            }
        }
    }

    // ── scrolling helpers ─────────────────────────────────────────────────

    fn scroll_up_panel(&mut self, panel: &Focus) {
        match panel {
            Focus::Peers => {
                if self.peers.is_empty() {
                    return;
                }
                let i = self
                    .peers_list_state
                    .selected()
                    .map(|i| i.saturating_sub(1))
                    .unwrap_or(0);
                self.peers_list_state.select(Some(i));
            }
            Focus::Log => {
                self.log_follow = false;
                self.log_scroll = self.log_scroll.saturating_sub(1);
            }
            Focus::Seed => {}
        }
    }

    fn scroll_down_panel(&mut self, panel: &Focus) {
        match panel {
            Focus::Peers => {
                if self.peers.is_empty() {
                    return;
                }
                let max = self.peers.len().saturating_sub(1);
                let i = self
                    .peers_list_state
                    .selected()
                    .map(|i| (i + 1).min(max))
                    .unwrap_or(0);
                self.peers_list_state.select(Some(i));
            }
            Focus::Log => {
                let max = self.log_lines.len().saturating_sub(1);
                self.log_scroll = (self.log_scroll + 1).min(max);
                if self.log_scroll >= max {
                    self.log_follow = true;
                }
            }
            Focus::Seed => {}
        }
    }

    fn scroll_left(&mut self) {
        if matches!(self.focus, Focus::Log) {
            self.log_col = self.log_col.saturating_sub(4);
        }
    }

    fn scroll_right(&mut self) {
        if matches!(self.focus, Focus::Log) {
            self.log_col += 4;
        }
    }

    fn scroll_by(&mut self, delta: isize) {
        let panel = self.focus.clone();
        self.scroll_by_panel(delta, &panel);
    }

    fn scroll_by_panel(&mut self, delta: isize, panel: &Focus) {
        if delta < 0 {
            for _ in 0..(-delta) {
                self.scroll_up_panel(panel);
            }
        } else {
            for _ in 0..delta {
                self.scroll_down_panel(panel);
            }
        }
    }

    // ── input handling ────────────────────────────────────────────────────

    fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) -> bool {
        match code {
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => return true,
            KeyCode::Char('q') if self.focus != Focus::Seed => return true,

            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Seed => Focus::Peers,
                    Focus::Peers => Focus::Log,
                    Focus::Log => Focus::Seed,
                };
                if self.focus == Focus::Peers
                    && self.peers_list_state.selected().is_none()
                    && !self.peers.is_empty()
                {
                    self.peers_list_state.select(Some(0));
                }
            }

            KeyCode::Enter => self.toggle_daemon(),

            KeyCode::Char(c) if self.focus == Focus::Seed => {
                let byte_pos = char_to_byte(&self.seed_input, self.seed_cursor);
                self.seed_input.insert(byte_pos, c);
                self.seed_cursor += 1;
            }
            KeyCode::Backspace if self.focus == Focus::Seed => {
                if self.seed_cursor > 0 {
                    self.seed_cursor -= 1;
                    let byte_pos = char_to_byte(&self.seed_input, self.seed_cursor);
                    self.seed_input.remove(byte_pos);
                }
            }
            KeyCode::Left if self.focus == Focus::Seed => {
                self.seed_cursor = self.seed_cursor.saturating_sub(1);
            }
            KeyCode::Right if self.focus == Focus::Seed => {
                self.seed_cursor = (self.seed_cursor + 1).min(self.seed_input.chars().count());
            }
            KeyCode::Left if self.focus == Focus::Log => self.scroll_left(),
            KeyCode::Right if self.focus == Focus::Log => self.scroll_right(),

            KeyCode::Up => self.scroll_by(-1),
            KeyCode::Down => self.scroll_by(1),
            KeyCode::PageUp => self.scroll_by(-10),
            KeyCode::PageDown => self.scroll_by(10),
            KeyCode::End => {
                if matches!(self.focus, Focus::Log) {
                    self.log_scroll = self.log_lines.len().saturating_sub(1);
                    self.log_col = 0;
                    self.log_follow = true;
                }
            }
            KeyCode::Home => {
                if matches!(self.focus, Focus::Log) {
                    self.log_scroll = 0;
                    self.log_col = 0;
                    self.log_follow = false;
                }
            }

            _ => {}
        }
        false
    }

    // ── rendering ─────────────────────────────────────────────────────────

    fn render(&mut self, f: &mut Frame) {
        let area = f.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);

        self.render_header(f, chunks[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(chunks[1]);

        self.render_peers(f, body[0]);
        self.render_log(f, body[1]);
    }

    fn render_header(&mut self, f: &mut Frame, area: Rect) {
        let (status_text, status_color) = match &self.daemon {
            DaemonState::Stopped => ("● Stopped", Color::DarkGray),
            DaemonState::Starting => ("◎ Starting…", Color::Yellow),
            DaemonState::Running { .. } => ("● Running", Color::Green),
            DaemonState::Stopping => ("◎ Stopping…", Color::Yellow),
        };

        let btn_label = match &self.daemon {
            DaemonState::Stopped | DaemonState::Stopping => " Start ",
            DaemonState::Running { .. } | DaemonState::Starting => " Stop  ",
        };
        let btn_style = match &self.daemon {
            DaemonState::Stopped | DaemonState::Stopping => {
                Style::default().fg(Color::Black).bg(Color::Green)
            }
            _ => Style::default().fg(Color::Black).bg(Color::Red),
        };

        let seed_focused = self.focus == Focus::Seed;
        let seed_display: String = if seed_focused {
            let mut s = self.seed_input.clone();
            let byte_pos = char_to_byte(&s, self.seed_cursor);
            s.insert(byte_pos, '│');
            s
        } else if self.seed_input.is_empty() {
            "─── Tab to focus, type seed, Enter to start ───".to_string()
        } else {
            obscure(&self.seed_input)
        };

        let overlay_info = match &self.daemon {
            DaemonState::Running { overlay, .. } if !overlay.is_empty() => {
                format!("  overlay: {overlay}")
            }
            _ => String::new(),
        };

        let inner = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(14),
                Constraint::Min(20),
                Constraint::Length(9),
            ])
            .split(area);

        let status = Paragraph::new(Line::from(Span::styled(
            format!(" {status_text} "),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        )))
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(status, inner[0]);

        let seed_border_style = if seed_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        let seed_para = Paragraph::new(Line::from(vec![
            Span::styled(" Seed: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                &seed_display,
                if seed_focused {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Gray)
                },
            ),
            Span::styled(&overlay_info, Style::default().fg(Color::DarkGray)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(seed_border_style)
                .title(" SeedNet ")
                .title_alignment(Alignment::Center),
        );
        f.render_widget(seed_para, inner[1]);

        let btn = Paragraph::new(Line::from(vec![
            Span::styled(btn_label, btn_style),
            Span::styled(" [↵]", Style::default().fg(Color::DarkGray)),
        ]))
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(btn, inner[2]);
    }

    fn render_peers(&mut self, f: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Peers;
        let remote_count = self.peers.iter().filter(|p| !p.is_local).count();
        let title = if focused {
            format!(" Peers ({remote_count}) [↑↓] ")
        } else {
            format!(" Peers ({remote_count}) ")
        };

        let items: Vec<ListItem> = if self.peers.is_empty() {
            vec![ListItem::new(Line::from(Span::styled(
                "  (no peers connected)",
                Style::default().fg(Color::DarkGray),
            )))]
        } else {
            self.peers
                .iter()
                .map(|p| {
                    if p.is_local {
                        let mut lines = vec![
                            Line::from(vec![
                                Span::styled("  ", Style::default()),
                                Span::styled(
                                    &p.id_short,
                                    Style::default()
                                        .fg(Color::Magenta)
                                        .add_modifier(Modifier::BOLD),
                                ),
                                Span::styled(" (you)", Style::default().fg(Color::DarkGray)),
                            ]),
                            Line::from(vec![
                                Span::styled("    overlay  ", Style::default().fg(Color::DarkGray)),
                                Span::styled(&p.overlay, Style::default().fg(Color::Magenta)),
                            ]),
                        ];
                        if !p.overlay_ipv6.is_empty() {
                            lines.push(Line::from(vec![
                                Span::styled("    ipv6     ", Style::default().fg(Color::DarkGray)),
                                Span::styled(&p.overlay_ipv6, Style::default().fg(Color::Magenta)),
                            ]));
                        }
                        if !p.hostname.is_empty() {
                            lines.push(Line::from(vec![
                                Span::styled("    hostname ", Style::default().fg(Color::DarkGray)),
                                Span::styled(&p.hostname, Style::default().fg(Color::DarkGray)),
                            ]));
                        }
                        ListItem::new(Text::from(lines))
                    } else {
                        let mut lines = vec![
                            Line::from(vec![
                                Span::styled("  ", Style::default()),
                                Span::styled(
                                    &p.id_short,
                                    Style::default()
                                        .fg(Color::Cyan)
                                        .add_modifier(Modifier::BOLD),
                                ),
                                if p.hostname.is_empty() {
                                    Span::raw("")
                                } else {
                                    Span::styled(
                                        format!("  {}", p.hostname),
                                        Style::default().fg(Color::White),
                                    )
                                },
                            ]),
                            Line::from(vec![
                                Span::styled("    overlay  ", Style::default().fg(Color::DarkGray)),
                                Span::styled(&p.overlay, Style::default().fg(Color::Green)),
                            ]),
                        ];
                        if !p.overlay_ipv6.is_empty() {
                            lines.push(Line::from(vec![
                                Span::styled("    ipv6     ", Style::default().fg(Color::DarkGray)),
                                Span::styled(&p.overlay_ipv6, Style::default().fg(Color::Green)),
                            ]));
                        }
                        let conn_color = if p.connection == "relay" {
                            Color::Yellow
                        } else {
                            Color::DarkGray
                        };
                        let conn_label = if p.connection == "relay" && !p.relay_via.is_empty() {
                            format!("relay via {}", p.relay_via)
                        } else {
                            p.connection.clone()
                        };
                        lines.push(Line::from(vec![
                            Span::styled("    conn     ", Style::default().fg(Color::DarkGray)),
                            Span::styled(conn_label, Style::default().fg(conn_color)),
                        ]));
                        lines.push(Line::from(vec![
                            Span::styled("    underlay ", Style::default().fg(Color::DarkGray)),
                            Span::styled(&p.underlay, Style::default().fg(Color::White)),
                        ]));
                        ListItem::new(Text::from(lines))
                    }
                })
                .collect()
        };

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(if focused {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    })
                    .title(title)
                    .title_style(Style::default().fg(Color::Cyan)),
            )
            .highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White));

        f.render_stateful_widget(list, area, &mut self.peers_list_state);
    }

    fn render_log(&mut self, f: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Log;
        let total = self.log_lines.len();

        // Clamp scroll position.
        if total == 0 {
            self.log_scroll = 0;
        } else {
            self.log_scroll = self.log_scroll.min(total - 1);
        }
        let scroll_row = self.log_scroll;
        let scroll_col = self.log_col;

        let follow_marker = if self.log_follow { " [follow]" } else { "" };
        let col_marker = if scroll_col > 0 {
            format!(" →{scroll_col}")
        } else {
            String::new()
        };
        let title = if focused {
            format!(
                " Log [{}/{}]{follow_marker}{col_marker} [↑↓←→ PgUp/Dn End] ",
                scroll_row + 1,
                total.max(1)
            )
        } else {
            format!(
                " Log [{}/{}]{follow_marker}{col_marker} ",
                scroll_row + 1,
                total.max(1)
            )
        };

        // Inner width available for text (minus borders).
        let inner_w = area.width.saturating_sub(2) as usize;

        // Build visible lines: start from scroll_row, take as many as fit.
        let visible_height = area.height.saturating_sub(2) as usize;
        let lines: Vec<Line> = self
            .log_lines
            .iter()
            .enumerate()
            .skip(scroll_row)
            .take(visible_height)
            .map(|(idx, l)| {
                let style = if l.contains("ERROR") || l.contains("error") {
                    Style::default().fg(Color::Red)
                } else if l.contains("WARN") || l.contains("warn") {
                    Style::default().fg(Color::Yellow)
                } else if l.contains("connected") || l.contains("handshake completed") {
                    Style::default().fg(Color::Green)
                } else if l.contains("disconnected") || l.contains("Stopped") {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::White)
                };

                // Horizontal slice: skip scroll_col chars, then take inner_w.
                let chars: Vec<char> = l.chars().collect();
                let visible: String = chars.iter().skip(scroll_col).take(inner_w).collect();

                // Highlight the currently selected (top-visible) line.
                let bg = if idx == scroll_row && focused {
                    style.bg(Color::DarkGray)
                } else {
                    style
                };
                Line::from(Span::styled(visible, bg))
            })
            .collect();

        let para = Paragraph::new(Text::from(lines)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(if focused {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                })
                .title(title)
                .title_style(Style::default().fg(Color::Yellow)),
        );

        f.render_widget(para, area);
    }
}

pub fn run(state_dir: PathBuf, exe_path: PathBuf) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(state_dir, exe_path);

    let result = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> anyhow::Result<()> {
    loop {
        app.poll();
        terminal.draw(|f| app.render(f))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && app.handle_key(key.code, key.modifiers)
        {
            if matches!(app.daemon, DaemonState::Running { .. }) {
                app.stop_daemon();
            }
            break;
        }
    }
    Ok(())
}

fn char_to_byte(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

fn obscure(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n <= 4 {
        "*".repeat(n)
    } else {
        format!(
            "{}…{}",
            chars[..2].iter().collect::<String>(),
            "*".repeat(n.saturating_sub(4))
        )
    }
}

fn chrono_time() -> String {
    #[cfg(unix)]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { libc::localtime_r(&secs, &mut tm) };
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
    #[cfg(not(unix))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let h = (secs % 86400) / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        format!("{h:02}:{m:02}:{s:02}")
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            // OSC: ESC ] ... BEL  or  ESC ] ... ESC \
            Some(']') => {
                chars.next();
                loop {
                    match chars.next() {
                        None | Some('\x07') => break,
                        Some('\x1b') => {
                            if chars.peek() == Some(&'\\') {
                                chars.next();
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
            // CSI and other Fe sequences: ESC <byte> ... letter
            _ => {
                for ch in chars.by_ref() {
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        }
    }
    out
}

#[cfg(unix)]
fn libc_getuid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(unix)]
fn libc_kill(pid: u32, sig: i32) -> i32 {
    unsafe { libc::kill(pid as libc::pid_t, sig) }
}
