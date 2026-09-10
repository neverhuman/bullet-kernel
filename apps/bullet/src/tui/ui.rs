use super::model::{palette_len, Model, View, UNKNOWN_SURFACES};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

pub(super) fn draw(frame: &mut Frame<'_>, model: &mut Model, color: bool) {
    let bg = if color {
        Color::Rgb(8, 16, 31)
    } else {
        Color::Reset
    };
    let text = if color {
        Color::Rgb(227, 237, 247)
    } else {
        Color::Reset
    };
    let cyan = if color {
        Color::Rgb(50, 220, 240)
    } else {
        Color::Reset
    };
    let amber = if color {
        Color::Rgb(255, 196, 77)
    } else {
        Color::Reset
    };
    let style = Style::default().fg(text).bg(bg);
    frame.render_widget(Block::default().style(style), frame.area());
    let areas = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(frame.area());
    frame.render_widget(
        Paragraph::new(model.status_lines())
            .style(style.fg(amber))
            .block(Block::default().borders(Borders::BOTTOM)),
        areas[0],
    );
    let panes = if areas[1].width >= 85 {
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(areas[1])
    } else {
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).split(areas[1])
    };
    let rows = model
        .rows
        .iter()
        .map(|row| ListItem::new(row.label.as_str()))
        .collect::<Vec<_>>();
    let mut selection = ListState::default().with_selected(model.selected());
    let list = List::new(rows)
        .block(Block::bordered().title(model.view.title()))
        .style(style)
        .highlight_style(style.fg(cyan).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, panes[0], &mut selection);
    let title = match (model.details_focus, model.raw_json) {
        (true, true) => "Details [focused · raw JSON]",
        (true, false) => "Details [focused]",
        (false, true) => "Details [raw JSON]",
        (false, false) => "Details",
    };
    frame.render_widget(
        Paragraph::new(model.selected_detail())
            .style(style)
            .wrap(Wrap { trim: false })
            .scroll((model.scroll, 0))
            .block(Block::bordered().title(title)),
        panes[1],
    );
    let message = model.error.as_deref().map(crate::client::terminal_text)
        .unwrap_or_else(|| "Ctrl+K navigate · Tab panes · j/k move · Enter detail · Esc back · r refresh · J raw JSON · ? help · Ctrl+C detach".into());
    frame.render_widget(
        Paragraph::new(message)
            .style(style.fg(amber))
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::TOP)),
        areas[2],
    );
    if model.palette {
        let height = (palette_len() as u16)
            .saturating_add(2)
            .min(frame.area().height);
        let area = centered(frame.area(), 62, height);
        frame.render_widget(Clear, area);
        let items = View::ALL
            .iter()
            .map(|v| ListItem::new(v.title()))
            .chain(UNKNOWN_SURFACES.iter().copied().map(ListItem::new))
            .collect::<Vec<_>>();
        let mut selected = ListState::default().with_selected(Some(model.palette_selection));
        frame.render_stateful_widget(
            List::new(items)
                .style(style)
                .block(Block::bordered().title("Navigate · Enter to open · Esc to close"))
                .highlight_style(style.fg(cyan).add_modifier(Modifier::BOLD))
                .highlight_symbol("> "),
            area,
            &mut selected,
        );
    }
    if model.help {
        let area = centered(frame.area(), 78, 16);
        frame.render_widget(Clear, area);
        frame.render_widget(Paragraph::new("Ctrl+K: jump list (Portal surface titles)\nTab: focus list or details\nArrows / j / k: move selection or scroll details\nEnter: mission → task → Attempt → details\nEscape: back; close palette or help\nr: request one snapshot refresh\nJ: toggle raw JSON in details\n?: this help\nCtrl+C: detach; farm work continues (STOP_UNIMPLEMENTED)\n\nCandidates are preserved subjects, not approval decisions.\nNative session controls and approval mutations require their durable backend.\nRecent events are a bounded audit tail; this view is polled every two seconds.")
            .style(style).wrap(Wrap { trim: true }).block(Block::bordered().title("Operator help")), area);
    }
}

fn centered(outer: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(outer.width);
    let height = height.min(outer.height);
    Rect::new(
        outer.x + (outer.width - width) / 2,
        outer.y + (outer.height - height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn monochrome_console_keeps_hold_unknown_and_keyboard_labels() {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
        let mut model = Model {
            error: Some("FARMD_UNAVAILABLE".into()),
            help: true,
            ..Model::default()
        };
        terminal
            .draw(|frame| draw(frame, &mut model, false))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(text.contains("HOLD"));
        assert!(text.contains("UNKNOWN"));
        assert!(text.contains("LIVE 0"));
        assert!(text.contains("UNBOUND"));
        assert!(text.contains("STOP_UNIMPLEMENTED"));
        assert!(text.contains("Ctrl+C"));
        assert!(!text.contains("VERIFIED"));
        assert!(terminal
            .backend()
            .buffer()
            .content
            .iter()
            .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
    }
}
