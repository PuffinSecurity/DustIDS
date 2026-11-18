#[allow(clippy::wildcard_imports)]
use ratatui::{
    prelude::*,
    widgets::{canvas::*, *},
};
use std::sync::atomic::Ordering;

use crate::app::App;
use atomic_counter::AtomicCounter;


pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(16),
        Constraint::Min(8),
    ]).split(f.size());
    
    draw_text(f, app, chunks[0]);
    draw_gauges(f, app, chunks[1]);
    draw_charts(f, app, chunks[2]);
}


fn draw_gauges(f: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::bordered().title(" Realtime Stats ");
    f.render_widget(block, area);

    let constraints = vec![Constraint::Percentage(70), Constraint::Percentage(30)];
    let chunks = Layout::horizontal(constraints).split(area);
    {
        let chunks = Layout::vertical([Constraint::Min(5), Constraint::Length(3)])
            .split(chunks[0]);

        let block_spark = Block::bordered().title(" Realtime RX: ");
        let sparkline_values: Vec<u64> = app.state.rx_per_tick.iter().map(|&num| num as u64).collect();
        let sparkline = Sparkline::default()
            .block(block_spark)
            .style(Style::default().fg(Color::Green))
            .data(&sparkline_values)
            .direction(RenderDirection::RightToLeft)
            .bar_set(symbols::bar::NINE_LEVELS);
        f.render_widget(sparkline, chunks[0]);

        let block_gauge = Block::bordered().title(" Analysis Buffer: ");
        let buffer_len: u32 = app.state.analysis_buffer_len.load(Ordering::SeqCst);
        let label = format!("{:}", buffer_len);
        let gauge = Gauge::default()
            .block(block_gauge)
            .gauge_style(
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::ITALIC | Modifier::BOLD),
            )
            .use_unicode(true)
            .label(label)
            .ratio((buffer_len as f64 / app.state.analysis_buffer_cap as f64));
        f.render_widget(gauge, chunks[1]);
    }

    // let block = Block::bordered();
    // f.render_widget(block, chunks[1]);
    let text = vec![
        text::Line::from(Span::from("Packets Received:")),
        text::Line::from(vec![
            Span::raw(">    "),
            Span::styled(
                format!("{:}  ", app.state.rx_per_sec.to_string()), 
                Style::default().fg(Color::LightYellow).bold()
            ),
            Span::italic(Span::raw("per second")),
        ]),
        text::Line::from(vec![
            Span::raw(">    "),
            
            Span::styled(
                format!("{:}  ", app.state.rx_total.get().to_string()), 
                Style::default().fg(Color::LightYellow).bold()
            ),
            Span::italic(Span::raw("in total")),
        ]),
        
        text::Line::from(Span::from("Packets Analyzed:")),
        text::Line::from(vec![
            Span::raw(">    "),
            Span::styled(
                format!("{:}  ", app.state.analyzed_per_sec.to_string()), 
                Style::default().fg(Color::LightBlue).bold()
            ),
            Span::italic(Span::raw("per second")),
        ]),
        text::Line::from(vec![
            Span::raw(">    "),
            Span::styled(
                format!("{:}  ", app.state.analyzed_total.get().to_string()), 
                Style::default().fg(Color::LightBlue).bold()
            ),
            Span::italic(Span::raw("in total")),
        ]),

        text::Line::from(Span::from("Packets Dropped:")),
        text::Line::from(vec![
            Span::raw(">    "),
            Span::styled(
                format!("{:}  ", app.state.rx_drop_per_sec.to_string()), 
                Style::default().fg(Color::LightRed).bold()
            ),
            Span::italic(Span::raw("per second")),
        ]),
        text::Line::from(vec![
            Span::raw(">    "),
            Span::styled(
                format!("{:}  ", app.state.rx_dropped.get().to_string()), 
                Style::default().fg(Color::LightRed).bold()
            ).into(),
            Span::italic(Span::raw("in total")),
        ]),
    ];
    let block = Block::bordered();
    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, chunks[1]);
}

#[allow(clippy::too_many_lines)]
fn draw_charts(f: &mut Frame, app: &mut App, area: Rect) {
    let constraints = vec![Constraint::Percentage(100)];
    let chunks = Layout::horizontal(constraints).split(area);
    {
        let chunks = Layout::vertical([Constraint::Percentage(100)])
            .split(chunks[0]);
        {
            let chunks =
                Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
                    .split(chunks[0]);

            // Draw Rulesets
            let rules: Vec<ListItem> = app.state
                .rule_sets
                .iter()
                .map(|i| ListItem::new(vec![text::Line::from(Span::raw(i))]))
                .collect();
            let rules = List::new(rules)
                .block(Block::bordered().title(" Rule Sets "))
                .highlight_style(Style::default().add_modifier(Modifier::BOLD))
                .highlight_symbol("> ");
            f.render_widget(rules, chunks[0]);

            let alerts = app.state.alerts.read().unwrap();
            let logs: Vec<ListItem> = alerts
                .iter()
                .map(|alert| {
                    let content = vec![text::Line::from(vec![
                        Span::styled(format!("{:<20}", alert.timestamp), Style::default()),
                        Span::styled(alert.rule.clone(), Style::default().fg(Color::LightRed)),
                    ])];
                    ListItem::new(content)
                })
                .collect();
            let logs = List::new(logs).block(Block::bordered().title(" Alerts "));
            f.render_widget(logs, chunks[1]);
        }
    }
}

fn draw_text(f: &mut Frame, app: &mut App, area: Rect) {
    let text = vec![
        text::Line::from(vec![
            Span::from("Interface: "),
            Span::styled(app.state.iface_name.to_string(), Style::default().fg(Color::LightYellow)),
            Span::raw(" RX Queues: "),
            Span::styled(app.state.iface_queues.to_string(), Style::default().fg(Color::LightYellow)),
            Span::raw(" Analyzer: "),
            Span::styled("Yara-X", Style::default().fg(Color::LightYellow)),
            Span::raw(" Analysis Threads: "),
            Span::styled(app.state.analysis_threads.to_string(), Style::default().fg(Color::LightYellow)),
            Span::raw(" Syslog Server: "),
            Span::styled(
                if app.state.syslog_server.to_string() == "" { "None" } else { &app.state.syslog_server }, 
                if app.state.syslog_server.to_string() == "" { Style::default().fg(Color::LightRed)  } else { Style::default().fg(Color::LightYellow) }
            ),
        ])
    ];
    let block = Block::bordered().title(Span::styled(
        "Dust IDS - By PuffinSecurity",
        Style::default()
            .fg(Color::LightYellow)
            .add_modifier(Modifier::BOLD),
    ));
    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}
