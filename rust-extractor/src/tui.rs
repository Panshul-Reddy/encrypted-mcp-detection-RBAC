//! TUI dashboard — live flow classification display using ratatui.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::capture::CaptureStats;


const MAX_DISPLAY_FLOWS: usize = 500;


#[derive(Debug, Clone)]
pub struct ClassifiedFlow {
    pub flow_display: String,
    pub label: u8,
    pub proba_mcp: f64,
    pub proba_noise: f64,
    pub pkt_count: usize,
    pub duration_s: f64,
    pub ground_truth: Option<u8>,
    pub inference_latency: Duration,
    pub classified_at: Instant,
    pub is_closed: bool,
}


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SortMode {
    Recent,
    Confidence,
    Duration,
    Packets,
}

impl SortMode {
    fn next(self) -> Self {
        match self {
            SortMode::Recent => SortMode::Confidence,
            SortMode::Confidence => SortMode::Duration,
            SortMode::Duration => SortMode::Packets,
            SortMode::Packets => SortMode::Recent,
        }
    }

    fn label(self) -> &'static str {
        match self {
            SortMode::Recent => "Recent",
            SortMode::Confidence => "Confidence",
            SortMode::Duration => "Duration",
            SortMode::Packets => "Packets",
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilterMode {
    All,
    McpOnly,
    NoiseOnly,
}

impl FilterMode {
    fn next(self) -> Self {
        match self {
            FilterMode::All => FilterMode::McpOnly,
            FilterMode::McpOnly => FilterMode::NoiseOnly,
            FilterMode::NoiseOnly => FilterMode::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            FilterMode::All => "All",
            FilterMode::McpOnly => "MCP Only",
            FilterMode::NoiseOnly => "Noise Only",
        }
    }
}


#[derive(Debug)]
pub struct TuiState {

    pub flows: VecDeque<ClassifiedFlow>,
    pub active_predictions: HashMap<String, (u8, Option<u8>)>,

    pub latency_samples: VecDeque<Duration>,

    pub total_mcp: u64,
    pub total_noise: u64,
    pub correct_predictions: u64,
    pub total_with_ground_truth: u64,

    pub start_time: Instant,

    pub paused: bool,

    pub sort_mode: SortMode,

    pub filter_mode: FilterMode,

    pub table_state: TableState,

    pub replay_mode: bool,

    pub replay_done: bool,
}

impl TuiState {
    pub fn new(replay_mode: bool) -> Self {
        Self {
            flows: VecDeque::new(),
            active_predictions: HashMap::new(),
            latency_samples: VecDeque::with_capacity(1000),
            total_mcp: 0,
            total_noise: 0,
            correct_predictions: 0,
            total_with_ground_truth: 0,
            start_time: Instant::now(),
            paused: false,
            sort_mode: SortMode::Recent,
            filter_mode: FilterMode::All,
            table_state: TableState::default(),
            replay_mode,
            replay_done: false,
        }
    }


    pub fn add_flow(&mut self, flow: ClassifiedFlow) {
        // Deduplicate using active_predictions
        if let Some((old_label, old_gt)) = self.active_predictions.get(&flow.flow_display) {
            if *old_label >= 1 {
                self.total_mcp = self.total_mcp.saturating_sub(1);
            } else {
                self.total_noise = self.total_noise.saturating_sub(1);
            }
            
            if let Some(gt) = old_gt {
                self.total_with_ground_truth = self.total_with_ground_truth.saturating_sub(1);
                if (*gt == 0 && *old_label == 0) || (*gt >= 1 && *old_label >= 1) {
                    self.correct_predictions = self.correct_predictions.saturating_sub(1);
                }
            }
        }

        if flow.label >= 1 {
            self.total_mcp += 1;
        } else {
            self.total_noise += 1;
        }


        if let Some(gt) = flow.ground_truth {
            self.total_with_ground_truth += 1;
            // Binary accuracy: Correct if both are Noise (0) or both are MCP (>=1)
            if (gt == 0 && flow.label == 0) || (gt >= 1 && flow.label >= 1) {
                self.correct_predictions += 1;
            }
        }
        
        if flow.is_closed {
            self.active_predictions.remove(&flow.flow_display);
        } else {
            self.active_predictions.insert(flow.flow_display.clone(), (flow.label, flow.ground_truth));
        }

        // Keep UI table clean
        if let Some(pos) = self.flows.iter().position(|f| f.flow_display == flow.flow_display) {
            self.flows.remove(pos);
        }


        self.latency_samples.push_back(flow.inference_latency);
        if self.latency_samples.len() > 1000 {
            self.latency_samples.pop_front();
        }


        self.flows.push_front(flow);
        if self.flows.len() > MAX_DISPLAY_FLOWS {
            self.flows.pop_back();
        }
    }


    pub fn latency_percentile(&self, p: f64) -> Duration {
        if self.latency_samples.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted: Vec<Duration> = self.latency_samples.iter().copied().collect();
        sorted.sort();
        let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    pub fn accuracy(&self) -> Option<f64> {
        if self.total_with_ground_truth > 0 {
            Some(self.correct_predictions as f64 / self.total_with_ground_truth as f64 * 100.0)
        } else {
            None
        }
    }
}


pub fn run_tui(
    state: Arc<Mutex<TuiState>>,
    capture_stats: Arc<CaptureStats>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> anyhow::Result<()> {

    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(100);

    loop {

        {
            let state_guard = state.lock().unwrap();
            terminal.draw(|f| render_ui(f, &state_guard, &capture_stats))?;
        }


        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let mut state_guard = state.lock().unwrap();
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            let _ = shutdown_tx.send(true);
                            break;
                        }
                        KeyCode::Char('p') => {
                            state_guard.paused = !state_guard.paused;
                        }
                        KeyCode::Char('s') => {
                            state_guard.sort_mode = state_guard.sort_mode.next();
                        }
                        KeyCode::Char('f') => {
                            state_guard.filter_mode = state_guard.filter_mode.next();
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            let i = state_guard
                                .table_state
                                .selected()
                                .map(|i| i + 1)
                                .unwrap_or(0);
                            state_guard.table_state.select(Some(i));
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            let i = state_guard
                                .table_state
                                .selected()
                                .and_then(|i| i.checked_sub(1))
                                .unwrap_or(0);
                            state_guard.table_state.select(Some(i));
                        }
                        _ => {}
                    }
                }
            }
        }


        {
            let state_guard = state.lock().unwrap();
            if state_guard.replay_mode && state_guard.replay_done {

            }
        }
    }


    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}


fn render_ui(f: &mut Frame, state: &TuiState, stats: &CaptureStats) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Header / stats
            Constraint::Min(10),   // Flow table
            Constraint::Length(3), // Footer / controls
        ])
        .split(f.area());

    render_header(f, chunks[0], state, stats);
    render_flow_table(f, chunks[1], state);
    render_footer(f, chunks[2], state);
}

fn render_header(f: &mut Frame, area: Rect, state: &TuiState, stats: &CaptureStats) {
    let elapsed = state.start_time.elapsed();
    let hours = elapsed.as_secs() / 3600;
    let minutes = (elapsed.as_secs() % 3600) / 60;
    let seconds = elapsed.as_secs() % 60;

    let total_classified = state.total_mcp + state.total_noise;
    let p50 = state.latency_percentile(50.0);
    let p95 = state.latency_percentile(95.0);

    let mode_indicator = if state.replay_mode {
        if state.replay_done {
            Span::styled(" REPLAY COMPLETE ", Style::default().fg(Color::Black).bg(Color::Green).bold())
        } else {
            Span::styled(" REPLAY ", Style::default().fg(Color::Black).bg(Color::Yellow).bold())
        }
    } else if state.paused {
        Span::styled(" PAUSED ", Style::default().fg(Color::Black).bg(Color::Red).bold())
    } else {
        Span::styled(" LIVE ", Style::default().fg(Color::Black).bg(Color::Green).bold())
    };

    let accuracy_str = match state.accuracy() {
        Some(acc) => format!("{:.1}%", acc),
        None => "—".to_string(),
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  MCP Traffic Analyzer  ", Style::default().fg(Color::Cyan).bold()),
            Span::raw("  "),
            mode_indicator,
        ]),
        Line::from(vec![
            Span::styled("  Uptime: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:02}:{:02}:{:02}", hours, minutes, seconds), Style::default().fg(Color::White)),
            Span::styled("  │  Pkts: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", stats.packets_matched()), Style::default().fg(Color::White)),
            Span::styled("  │  Active Flows: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", stats.flows_created()), Style::default().fg(Color::White)),
            Span::styled("  │  Classified: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", total_classified), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  MCP: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", state.total_mcp), Style::default().fg(Color::Cyan).bold()),
            Span::styled("  │  Noise: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", state.total_noise), Style::default().fg(Color::DarkGray)),
            Span::styled("  │  Accuracy: ", Style::default().fg(Color::DarkGray)),
            Span::styled(accuracy_str, Style::default().fg(Color::Green).bold()),
            Span::styled("  │  Inference p50/p95: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.1}/{:.1}ms", p50.as_secs_f64() * 1000.0, p95.as_secs_f64() * 1000.0),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];

    let header = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " ◈ live-analyzer ",
                Style::default().fg(Color::Cyan).bold(),
            )),
    );
    f.render_widget(header, area);
}

fn render_flow_table(f: &mut Frame, area: Rect, state: &TuiState) {

    let filtered: Vec<&ClassifiedFlow> = state
        .flows
        .iter()
        .filter(|f| match state.filter_mode {
            FilterMode::All => true,
            FilterMode::McpOnly => f.label >= 1,
            FilterMode::NoiseOnly => f.label == 0,
        })
        .collect();


    let mut sorted = filtered;
    match state.sort_mode {
        SortMode::Recent => {}

        SortMode::Confidence => {
            sorted.sort_by(|a, b| b.proba_mcp.partial_cmp(&a.proba_mcp).unwrap());
        }
        SortMode::Duration => {
            sorted.sort_by(|a, b| b.duration_s.partial_cmp(&a.duration_s).unwrap());
        }
        SortMode::Packets => {
            sorted.sort_by(|a, b| b.pkt_count.cmp(&a.pkt_count));
        }
    }

    let header = Row::new(vec![
        Cell::from("Flow").style(Style::default().fg(Color::White).bold()),
        Cell::from("Class").style(Style::default().fg(Color::White).bold()),
        Cell::from("P(MCP)").style(Style::default().fg(Color::White).bold()),
        Cell::from("Pkts").style(Style::default().fg(Color::White).bold()),
        Cell::from("Duration").style(Style::default().fg(Color::White).bold()),
        Cell::from("GT").style(Style::default().fg(Color::White).bold()),
        
        Cell::from("Latency").style(Style::default().fg(Color::White).bold()),
    ]);

    let rows: Vec<Row> = sorted
        .iter()
        .map(|flow| {
            let (class_text, class_style) = if flow.label >= 1 {
                ("MCP", Style::default().fg(Color::Cyan).bold())
            } else {
                ("NOISE", Style::default().fg(Color::DarkGray))
            };

            let proba_style = if flow.proba_mcp > 0.9 {
                Style::default().fg(Color::Green)
            } else if flow.proba_mcp > 0.5 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let gt_text = match flow.ground_truth {
                Some(0) => "NSE",
                Some(1..=6) => "MCP",
                _ => "—",
            };
            let gt_style = match flow.ground_truth {
                Some(gt) if (gt == 0 && flow.label == 0) || (gt >= 1 && flow.label >= 1) => Style::default().fg(Color::Green),
                Some(_) => Style::default().fg(Color::Red).bold(),
                None => Style::default().fg(Color::DarkGray),
            };

            Row::new(vec![
                Cell::from(flow.flow_display.clone()),
                Cell::from(class_text).style(class_style),
                Cell::from(format!("{:.3}", flow.proba_mcp)).style(proba_style),
                Cell::from(format!("{}", flow.pkt_count)),
                Cell::from(format!("{:.1}s", flow.duration_s)),
                Cell::from(gt_text).style(gt_style),
                Cell::from(format!("{:.1}ms", flow.inference_latency.as_secs_f64() * 1000.0)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(28),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Length(9),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                format!(
                    " Flows [sort: {} | filter: {}] ",
                    state.sort_mode.label(),
                    state.filter_mode.label()
                ),
                Style::default().fg(Color::White),
            )),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    let mut table_state = state.table_state.clone();
    f.render_stateful_widget(table, area, &mut table_state);
}

fn render_footer(f: &mut Frame, area: Rect, state: &TuiState) {
    let controls = if state.replay_mode && state.replay_done {
        vec![
            Span::styled("  [q]", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" Quit  "),
            Span::styled("[s]", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" Sort  "),
            Span::styled("[f]", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" Filter  "),
            Span::styled("[↑↓/jk]", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" Scroll  "),
        ]
    } else {
        vec![
            Span::styled("  [q]", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" Quit  "),
            Span::styled("[p]", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" Pause  "),
            Span::styled("[s]", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" Sort  "),
            Span::styled("[f]", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" Filter  "),
            Span::styled("[↑↓/jk]", Style::default().fg(Color::Yellow).bold()),
            Span::raw(" Scroll  "),
        ]
    };

    let footer = Paragraph::new(Line::from(controls)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, area);
}
