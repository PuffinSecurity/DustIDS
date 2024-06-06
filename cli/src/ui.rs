#[allow(clippy::wildcard_imports)]
use ratatui::{
    prelude::*,
    widgets::{canvas::*, *},
};
use std::sync::atomic::Ordering;

use crate::app::App;

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(10),
        Constraint::Min(8),
    ]).split(f.size());
    
    draw_text(f, app, chunks[0]);
    draw_gauges(f, app, chunks[1]);
    draw_charts(f, app, chunks[2]);
}


fn draw_gauges(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(8),
        // Constraint::Length(8),
        Constraint::Length(2),
    ])
    .margin(1)
    .split(area);
    let block = Block::bordered().title("Graphs");
    f.render_widget(block, area);
    // ////////////////////////////////////////////////////////////////////////
    // let x_labels = vec![
    //     Span::styled(
    //         format!("{}", app.window[0]),
    //         Style::default().add_modifier(Modifier::BOLD),
    //     ),
    //     Span::raw(format!("{}", (app.window[0] + app.window[1]) / 2.0)),
    //     Span::styled(
    //         format!("{}", app.window[1]),
    //         Style::default().add_modifier(Modifier::BOLD),
    //     ),
    // ];

    // let datasets = vec![
    //     Dataset::default()
    //         .name("data2")
    //         .marker(symbols::Marker::Dot)
    //         .style(Style::default().fg(Color::Cyan))
    //         .data(&app.data1),
    //     Dataset::default()
    //         .name("data3")
    //         .marker(symbols::Marker::Braille)
    //         .style(Style::default().fg(Color::Yellow))
    //         .data(&app.data2),
    // ];

    // let chart = Chart::new(datasets)
    //     .block(Block::bordered().title("Chart 1".cyan().bold()))
    //     .x_axis(
    //         Axis::default()
    //             .title("X Axis")
    //             .style(Style::default().fg(Color::Gray))
    //             .labels(x_labels)
    //             .bounds(app.window),
    //     )
    //     .y_axis(
    //         Axis::default()
    //             .title("Y Axis")
    //             .style(Style::default().fg(Color::Gray))
    //             .labels(vec!["-20".bold(), "0".into(), "20".bold()])
    //             .bounds([-20.0, 20.0]),
    //     );

    // f.render_widget(chart, area);

    // ////////////////////////////////////////////////////////////////////

    let sparkline_values: Vec<u64> = app.state.rx_per_tick.iter().map(|&num| num as u64).collect();
    let sparkline = Sparkline::default()
        .block(Block::new().title("Realtime RX:"))
        .style(Style::default().fg(Color::Green))
        .data(&sparkline_values)
        .direction(RenderDirection::RightToLeft)
        .bar_set(symbols::bar::NINE_LEVELS);
    f.render_widget(sparkline, chunks[0]);

    let buffer_len: u32 = app.state.analysis_buffer_len.load(Ordering::SeqCst);
    let label = format!("{:}", buffer_len);
    let gauge = Gauge::default()
        .block(Block::new().title("Analysis Buffer:"))
        .gauge_style(
            Style::default()
                .fg(Color::LightYellow)
                .bg(Color::Black)
                .add_modifier(Modifier::ITALIC | Modifier::BOLD),
        )
        .use_unicode(true)
        .label(label)
        .ratio((buffer_len as f64 / app.state.analysis_buffer_cap as f64));
    f.render_widget(gauge, chunks[1]);
}

#[allow(clippy::too_many_lines)]
fn draw_charts(f: &mut Frame, app: &mut App, area: Rect) {
    let constraints = vec![Constraint::Percentage(100)];
    let chunks = Layout::horizontal(constraints).split(area);
    {
        let chunks = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
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
