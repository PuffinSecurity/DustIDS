#[allow(clippy::wildcard_imports)]
use ratatui::{
    prelude::*,
    widgets::{canvas::*, *},
};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(f.size());
    
    draw_text(f, chunks[0]);
    draw_first_tab(f, app, chunks[1]);
}

fn draw_first_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(10),
        Constraint::Min(8),
    ])
    .split(area);
    draw_gauges(f, app, chunks[0]);
    draw_charts(f, app, chunks[1]);
}

fn draw_gauges(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(8),
        Constraint::Length(2),
    ])
    .margin(1)
    .split(area);
    let block = Block::bordered().title("Graphs");
    f.render_widget(block, area);

    let sparkline = Sparkline::default()
        .block(Block::new().title("Realtime RX:"))
        .style(Style::default().fg(Color::Green))
        .data(&app.rx_per_sec[..])
        .direction(RenderDirection::RightToLeft)
        .bar_set(if app.enhanced_graphics {
            symbols::bar::NINE_LEVELS
        } else {
            symbols::bar::THREE_LEVELS
        });
    f.render_widget(sparkline, chunks[0]);

    let label = format!("{:}", app.analysis_buffer);
    let gauge = Gauge::default()
        .block(Block::new().title("Analysis Buffer:"))
        .gauge_style(
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Black)
                .add_modifier(Modifier::ITALIC | Modifier::BOLD),
        )
        .use_unicode(app.enhanced_graphics)
        .label(label)
        .ratio(app.progress);
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

            // Draw tasks
            let tasks: Vec<ListItem> = app
                .tasks
                .items
                .iter()
                .map(|i| ListItem::new(vec![text::Line::from(Span::raw(*i))]))
                .collect();
            let tasks = List::new(tasks)
                .block(Block::bordered().title(" Rule Sets "))
                .highlight_style(Style::default().add_modifier(Modifier::BOLD))
                .highlight_symbol("> ");
            f.render_stateful_widget(tasks, chunks[0], &mut app.tasks.state);

            // Draw logs
            let warning_style = Style::default().fg(Color::Yellow);
            let logs: Vec<ListItem> = app
                .logs
                .iter()
                .map(|(ts, name)| {
                    let content = vec![text::Line::from(vec![
                        Span::styled(format!("{:<20}", ts), Style::default()),
                        Span::styled(name, warning_style),
                    ])];
                    ListItem::new(content)
                })
                .collect();
            let logs = List::new(logs).block(Block::bordered().title(" Alerts "));
            f.render_widget(logs, chunks[1]);
        }
    }
}

fn draw_text(f: &mut Frame, area: Rect) {
    let text = vec![
        text::Line::from(vec![
            Span::from("Interface: "),
            Span::styled("Loopback", Style::default().fg(Color::Green)),
            Span::raw(" RX Queues: "),
            Span::styled("1", Style::default().fg(Color::Yellow)),
            Span::raw(" Analyzer: "),
            Span::styled("Yara-X", Style::default().fg(Color::Green)),
            Span::raw(" Analysis Threads: "),
            Span::styled("6", Style::default().fg(Color::Yellow)),
        ])
    ];
    let block = Block::bordered().title(Span::styled(
        "Dust IDS - By PuffinSecurity",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ));
    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}
