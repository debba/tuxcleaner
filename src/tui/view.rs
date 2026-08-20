use super::*;

pub(super) fn draw_home(frame: &mut Frame<'_>, state: &mut ListState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.area());
    let title = Paragraph::new(vec![
        Line::from(Span::styled(
            "TuxCleaner",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("Safety-first Linux maintenance"),
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::BOTTOM));
    frame.render_widget(title, chunks[0]);

    let items: Vec<_> = MENU
        .iter()
        .map(|(_, title, detail)| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{title:<10}"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(*detail),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(Block::default().title(" Actions ").borders(Borders::ALL))
        .highlight_symbol("▶ ")
        .highlight_style(Style::default().fg(Color::Yellow));
    frame.render_stateful_widget(list, chunks[1], state);

    let help = Paragraph::new("↑/↓ or j/k: move   Enter: open   q/Esc: quit")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::TOP));
    frame.render_widget(help, chunks[2]);
}

pub(super) fn draw_workflow(frame: &mut Frame<'_>, state: &mut WorkflowState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(frame.area());
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                format!("TuxCleaner › {}", action_title(state.action)),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(action_subtitle(state.action)),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::BOTTOM)),
        chunks[0],
    );

    if state.loading.is_some() || state.preparing.is_some() || state.executing.is_some() {
        let spinner = ["⠋", "⠙", "⠹", "⠸"][state.spinner];
        frame.render_widget(
            Paragraph::new(format!("\n  {spinner} {}", state.status))
                .block(Block::default().title(" Progress ").borders(Borders::ALL)),
            chunks[1],
        );
    } else if let Some(data) = &state.data {
        let items = workflow_items(data, &state.selected);
        let list = List::new(items)
            .block(Block::default().title(" Details ").borders(Borders::ALL))
            .highlight_symbol("▶ ")
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
        frame.render_stateful_widget(list, chunks[1], &mut state.list_state);
    }

    let mut footer = vec![Line::from(state.status.clone())];
    if workflow_is_selectable(state.data.as_ref()) {
        footer.push(Line::from("↑/↓ move   Space select   Enter review"));
        footer.push(Line::from("r refresh   Esc/q back"));
    } else if matches!(state.data, Some(WorkflowData::Update(_))) {
        footer.push(Line::from("Enter install update   r check again"));
        footer.push(Line::from("Esc/q back"));
    } else {
        footer.push(Line::from("↑/↓ scroll   r refresh   Esc/q back"));
    }
    frame.render_widget(
        Paragraph::new(footer)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::TOP)),
        chunks[2],
    );

    if state.confirming {
        draw_workflow_confirmation(frame, state);
    } else if let Some(result) = &state.result {
        draw_workflow_result(frame, result);
    } else if let Some(error) = &state.error {
        draw_overlay(
            frame,
            " Error ",
            vec![
                Line::from(Span::styled(
                    "Operation failed",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(error.clone()),
                Line::from(""),
                Line::from("Enter or Esc: continue"),
            ],
            76,
            11,
        );
    }
}

pub(super) fn workflow_items(
    data: &WorkflowData,
    selected: &BTreeSet<usize>,
) -> Vec<ListItem<'static>> {
    match data {
        WorkflowData::Clean(report) => report
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                ListItem::new(format!(
                    "{} {:>10}  {} · {}",
                    selection_marker(selected.contains(&index), true),
                    format_bytes(item.estimated_bytes),
                    item.group,
                    item.label
                ))
            })
            .collect(),
        WorkflowData::Uninstall(report) => report
            .applications
            .iter()
            .enumerate()
            .map(|(index, application)| {
                ListItem::new(format!(
                    "{} {:>10}  {} · {} · {}",
                    selection_marker(selected.contains(&index), true),
                    format_bytes(application.installed_bytes),
                    truncate_text(&application.name, 30),
                    application.source,
                    application.package
                ))
            })
            .collect(),
        WorkflowData::Purge(candidates) => candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                ListItem::new(format!(
                    "{} {:>10}  {} · {} days · {}",
                    selection_marker(selected.contains(&index), true),
                    format_bytes(candidate.size),
                    candidate.kind,
                    candidate.age_days,
                    candidate.path.display()
                ))
            })
            .collect(),
        WorkflowData::Status(report) => status_lines(report)
            .into_iter()
            .map(ListItem::new)
            .collect(),
        WorkflowData::History(records) => records
            .iter()
            .map(|record| {
                let succeeded = record
                    .results
                    .iter()
                    .filter(|result| result.success)
                    .count();
                let bytes: u64 = record
                    .results
                    .iter()
                    .filter(|result| result.success && !result.dry_run)
                    .map(|result| result.estimated_bytes)
                    .sum();
                ListItem::new(format!(
                    "{}  {:<20}  {}/{} succeeded  {}",
                    record.timestamp.format("%Y-%m-%d %H:%M UTC"),
                    record.command,
                    succeeded,
                    record.results.len(),
                    format_bytes(bytes)
                ))
            })
            .collect(),
        WorkflowData::Update(info) => vec![
            ListItem::new(format!("Installed version   {}", info.current_version)),
            ListItem::new(format!("Available version   {}", info.available_version)),
            ListItem::new(format!("Target              {}", info.target)),
            ListItem::new(if info.update_available {
                "An update is available. Press Enter to review installation."
            } else {
                "TuxCleaner is already up to date."
            }),
        ],
    }
}

pub(super) fn status_lines(report: &SystemStatus) -> Vec<String> {
    let mut lines = vec![
        format!("Host       {}", report.hostname),
        format!(
            "CPU        {} logical cores · load {:.2} / {:.2} / {:.2}",
            report.logical_cpus,
            report.load_average[0],
            report.load_average[1],
            report.load_average[2]
        ),
        format!(
            "Memory     {} / {} used ({:.1}%)",
            format_bytes(report.memory.used_bytes),
            format_bytes(report.memory.total_bytes),
            report.memory.used_percent
        ),
        format!("Uptime     {}", format_tui_duration(report.uptime_seconds)),
        String::new(),
        "Disks".into(),
    ];
    lines.extend(report.disks.iter().map(|disk| {
        format!(
            "  {:<20} {:>10} / {:>10} ({:>5.1}%)",
            disk.mount,
            format_bytes(disk.used_bytes),
            format_bytes(disk.total_bytes),
            disk.used_percent
        )
    }));
    lines
}

pub(super) fn draw_workflow_confirmation(frame: &mut Frame<'_>, state: &WorkflowState) {
    let (title, summary, warning) = match state.data.as_ref() {
        Some(WorkflowData::Clean(_)) => (
            " Confirm cleanup ",
            format!(
                "Clean {} selected item(s), {}?",
                state.selected.len(),
                format_bytes(selected_workflow_bytes(
                    state.data.as_ref(),
                    &state.selected
                ))
            ),
            "Caches and other rebuildable data will be permanently removed.",
        ),
        Some(WorkflowData::Uninstall(_)) => (
            " Confirm uninstall ",
            format!(
                "Uninstall {} selected application(s)?",
                state.selected.len()
            ),
            "The reviewed package-manager plan will run. User data is preserved.",
        ),
        Some(WorkflowData::Purge(_)) => (
            " Confirm purge ",
            format!(
                "Permanently remove {} artifact(s), {}?",
                state.selected.len(),
                format_bytes(selected_workflow_bytes(
                    state.data.as_ref(),
                    &state.selected
                ))
            ),
            "Build artifacts will be permanently removed.",
        ),
        Some(WorkflowData::Update(info)) => (
            " Confirm update ",
            format!(
                "Replace TuxCleaner {} with {}?",
                info.current_version, info.available_version
            ),
            "The release archive will be checksum-verified before replacement.",
        ),
        _ => return,
    };
    let mut lines = vec![
        Line::from(Span::styled(
            summary,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(warning),
    ];
    if !state.previews.is_empty() {
        lines.push(Line::from(""));
        for preview in state.previews.iter().take(3) {
            lines.push(Line::from(preview.command.clone()));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Enter: confirm   Esc: cancel"));
    draw_overlay(frame, title, lines, 78, 12);
}

pub(super) fn draw_workflow_result(frame: &mut Frame<'_>, result: &WorkflowResult) {
    let lines = match result {
        WorkflowResult::Actions(results) => {
            let succeeded = results.iter().filter(|result| result.success).count();
            let bytes: u64 = results
                .iter()
                .filter(|result| result.success)
                .map(|result| result.estimated_bytes)
                .sum();
            let mut lines = vec![
                Line::from(Span::styled(
                    format!("{succeeded}/{} operations succeeded", results.len()),
                    Style::default()
                        .fg(if succeeded == results.len() {
                            Color::Green
                        } else {
                            Color::Yellow
                        })
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(format!("Estimated space covered: {}", format_bytes(bytes))),
                Line::from(""),
            ];
            for result in results.iter().filter(|result| !result.success).take(3) {
                lines.push(Line::from(format!("Failed: {}", result.message)));
            }
            lines.push(Line::from("Enter or Esc: return to the main menu"));
            lines
        }
        WorkflowResult::Update(result) => vec![
            Line::from(Span::styled(
                if result.updated {
                    "TuxCleaner updated"
                } else {
                    "TuxCleaner is already up to date"
                },
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "{} → {} ({})",
                result.previous_version, result.installed_version, result.target
            )),
            Line::from(""),
            Line::from("Enter or Esc: return to the main menu"),
        ],
    };
    draw_overlay(frame, " Result ", lines, 76, 13);
}

pub(super) fn workflow_len(data: &WorkflowData) -> usize {
    match data {
        WorkflowData::Clean(report) => report.items.len(),
        WorkflowData::Uninstall(report) => report.applications.len(),
        WorkflowData::Purge(candidates) => candidates.len(),
        WorkflowData::Status(report) => status_lines(report).len(),
        WorkflowData::History(records) => records.len(),
        WorkflowData::Update(_) => 4,
    }
}

pub(super) fn workflow_is_selectable(data: Option<&WorkflowData>) -> bool {
    matches!(
        data,
        Some(WorkflowData::Clean(_) | WorkflowData::Uninstall(_) | WorkflowData::Purge(_))
    )
}

pub(super) fn workflow_is_actionable(data: Option<&WorkflowData>) -> bool {
    workflow_is_selectable(data)
        || matches!(data, Some(WorkflowData::Update(info)) if info.update_available)
}

pub(super) fn selected_workflow_bytes(
    data: Option<&WorkflowData>,
    selected: &BTreeSet<usize>,
) -> u64 {
    match data {
        Some(WorkflowData::Clean(report)) => selected
            .iter()
            .filter_map(|index| report.items.get(*index))
            .map(|item| item.estimated_bytes)
            .sum(),
        Some(WorkflowData::Uninstall(report)) => selected
            .iter()
            .filter_map(|index| report.applications.get(*index))
            .map(|application| application.installed_bytes)
            .sum(),
        Some(WorkflowData::Purge(candidates)) => selected
            .iter()
            .filter_map(|index| candidates.get(*index))
            .map(|candidate| candidate.size)
            .sum(),
        _ => 0,
    }
}

pub(super) fn workflow_ready_status(data: &WorkflowData) -> String {
    match data {
        WorkflowData::Clean(report) => format!(
            "{} candidates · {} estimated",
            report.items.len(),
            format_bytes(report.estimated_total_bytes)
        ),
        WorkflowData::Uninstall(report) => {
            format!("{} installed applications", report.applications.len())
        }
        WorkflowData::Purge(candidates) => format!(
            "{} old artifacts · {}",
            candidates.len(),
            format_bytes(candidates.iter().map(|candidate| candidate.size).sum())
        ),
        WorkflowData::Status(_) => "Read-only system snapshot".into(),
        WorkflowData::History(records) => format!("{} recent operations", records.len()),
        WorkflowData::Update(info) if info.update_available => {
            format!("Version {} is available", info.available_version)
        }
        WorkflowData::Update(_) => "TuxCleaner is up to date".into(),
    }
}

pub(super) fn action_title(action: MenuAction) -> &'static str {
    MENU.iter()
        .find(|(candidate, _, _)| *candidate == action)
        .map(|(_, title, _)| *title)
        .unwrap_or("TuxCleaner")
}

pub(super) fn action_subtitle(action: MenuAction) -> &'static str {
    MENU.iter()
        .find(|(candidate, _, _)| *candidate == action)
        .map(|(_, _, detail)| *detail)
        .unwrap_or_default()
}

pub(super) fn truncate_text(value: &str, maximum: usize) -> String {
    let mut characters = value.chars();
    let prefix: String = characters
        .by_ref()
        .take(maximum.saturating_sub(1))
        .collect();
    if characters.next().is_some() {
        format!("{prefix}…")
    } else {
        value.to_owned()
    }
}

pub(super) fn format_tui_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    format!("{days}d {hours}h {minutes}m")
}

pub(super) fn draw_analyze(frame: &mut Frame<'_>, state: &mut AnalyzeState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(frame.area());
    // Extract everything needed from the active location up front, as owned/copy values, so no
    // borrow of `state.locations` is held live across the later `&mut state.list_state` use.
    let path_display = state.active().path.display().to_string();
    let total_size = state.active().total_size;
    let total_files = state.active().total_files;
    let has_data = state.active_has_data();
    let complete = state.active().complete;
    let is_scanning = state.active().scan.is_some();
    let error = state.active().error.clone();

    let title = if has_data {
        let suffix = if is_scanning && !complete {
            " (scanning…)"
        } else {
            ""
        };
        vec![
            Line::from(Span::styled(
                "TuxCleaner › Analyze",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "{path_display}  ·  {} across {total_files} files{suffix}",
                format_bytes(total_size),
            )),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                "TuxCleaner › Analyze",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(path_display),
        ]
    };
    frame.render_widget(
        Paragraph::new(title)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::BOTTOM)),
        chunks[0],
    );

    if !has_data && !complete && error.is_none() {
        let spinner = ["⠋", "⠙", "⠹", "⠸"][state.spinner];
        frame.render_widget(
            Paragraph::new(format!("\n  {spinner} Scanning disk usage..."))
                .block(Block::default().title(" Files ").borders(Borders::ALL)),
            chunks[1],
        );
    } else if let Some(error) = &error {
        frame.render_widget(
            Paragraph::new(format!("\n  Scan failed: {error}"))
                .style(Style::default().fg(Color::Red))
                .wrap(Wrap { trim: false })
                .block(Block::default().title(" Files ").borders(Borders::ALL)),
            chunks[1],
        );
    } else {
        let items = state.render_items();
        let title = match state.mode {
            AnalyzeMode::Browse => " Files ",
            AnalyzeMode::TopFiles => " Top large files ",
        };
        let list = List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_symbol("▶ ")
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
        frame.render_stateful_widget(list, chunks[1], &mut state.list_state);
    }

    let selected_total: u64 = state.selected_files.values().sum();
    let filter = if state.filtering {
        format!("Filter: {}▌", state.filter)
    } else if !state.filter.is_empty() {
        format!("Filter: {}", state.filter)
    } else if state.selected_files.is_empty() {
        state.status.clone()
    } else {
        format!(
            "{} selected · {}",
            state.selected_files.len(),
            format_bytes(selected_total)
        )
    };
    let mut footer = vec![Line::from(filter)];
    if state.filtering {
        footer.push(Line::from("Type to filter   Enter: apply   Esc: clear"));
    } else {
        footer.push(Line::from(
            "↑/↓ move   Enter open   Space select   d Delete   / filter",
        ));
        footer.push(Line::from("t top   r refresh   Esc back   ? help   q quit"));
    }
    frame.render_widget(
        Paragraph::new(footer)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::TOP)),
        chunks[2],
    );

    if state.confirming_delete {
        draw_delete_confirmation(frame, state);
    } else if let Some(results) = &state.results {
        draw_results(frame, results);
    } else if state.show_help {
        draw_help(frame);
    }
}

pub(super) fn disk_item(
    entry: &DiskEntry,
    total: u64,
    selected: bool,
    selectable: bool,
) -> ListItem<'static> {
    let marker = selection_marker(selected, selectable);
    let percent = percentage(entry.size, total);
    let icon = if entry.is_dir { "▸" } else { " " };
    let label = format!(
        "{marker} {:>5.1}% {} {icon} {}  {:>10}",
        percent,
        progress_bar(percent, 12),
        entry.name,
        format_bytes(entry.size)
    );
    ListItem::new(label)
}

pub(super) fn file_item(
    file: &LargeFile,
    total: u64,
    selected: bool,
    selectable: bool,
) -> ListItem<'static> {
    let marker = selection_marker(selected, selectable);
    let percent = percentage(file.size, total);
    let label = format!(
        "{marker} {:>5.1}% {}   {}  {:>10}",
        percent,
        progress_bar(percent, 12),
        file.path.display(),
        format_bytes(file.size)
    );
    ListItem::new(label)
}

pub(super) fn selection_marker(selected: bool, selectable: bool) -> &'static str {
    if selected {
        "●"
    } else if selectable {
        "○"
    } else {
        " "
    }
}

pub(super) fn percentage(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 * 100.0 / total as f64
    }
}

pub(super) fn progress_bar(percent: f64, width: usize) -> String {
    let filled = ((percent.clamp(0.0, 100.0) / 100.0) * width as f64).round() as usize;
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

pub(super) fn is_selectable_personal_file(
    home: &Path,
    path: &Path,
    is_dir: bool,
    size: u64,
) -> bool {
    if is_dir || size < ANALYZE_MINIMUM_SIZE || !path.starts_with(home) {
        return false;
    }
    let Ok(relative) = path.strip_prefix(home) else {
        return false;
    };
    !relative.components().any(|component| {
        matches!(component, Component::Normal(name) if name.to_string_lossy().starts_with('.'))
    }) && !relative.starts_with("go/pkg")
}

pub(super) fn draw_delete_confirmation(frame: &mut Frame<'_>, state: &AnalyzeState) {
    let total: u64 = state.pending_delete.values().sum();
    let detail = if state.pending_delete.len() == 1 {
        state
            .pending_delete
            .keys()
            .next()
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    } else {
        format!("{} selected files", state.pending_delete.len())
    };
    let text = vec![
        Line::from(Span::styled(
            "Permanently remove?",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(detail),
        Line::from(format!("Total: {}", format_bytes(total))),
        Line::from(""),
        Line::from("Enter: confirm   Esc: cancel"),
    ];
    draw_overlay(frame, " Confirm removal ", text, 70, 9);
}

pub(super) fn draw_results(frame: &mut Frame<'_>, results: &[ActionResult]) {
    let succeeded = results.iter().filter(|result| result.success).count();
    let total: u64 = results
        .iter()
        .filter(|result| result.success)
        .map(|result| result.estimated_bytes)
        .sum();
    let mut text = vec![
        Line::from(Span::styled(
            format!("{succeeded}/{} permanently removed", results.len()),
            Style::default()
                .fg(if succeeded == results.len() {
                    Color::Green
                } else {
                    Color::Yellow
                })
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("Space covered: {}", format_bytes(total))),
        Line::from(""),
    ];
    for result in results.iter().filter(|result| !result.success).take(3) {
        text.push(Line::from(format!("Failed: {}", result.message)));
    }
    text.push(Line::from("Enter or Esc: continue"));
    draw_overlay(frame, " Result ", text, 70, 9);
}

pub(super) fn draw_help(frame: &mut Frame<'_>) {
    let text = vec![
        Line::from("↑/↓ or j/k     Move selection"),
        Line::from("Enter or →     Open directory"),
        Line::from("Space          Select a personal file"),
        Line::from("d/Delete       Permanently remove selection"),
        Line::from("/              Filter current list"),
        Line::from("t              Toggle top large files"),
        Line::from("r              Refresh current location"),
        Line::from("Esc or ←       Back"),
        Line::from("q              Quit TuxCleaner"),
        Line::from(""),
        Line::from("Press ? or Esc to close"),
    ];
    draw_overlay(frame, " Analyze help ", text, 66, 15);
}

pub(super) fn draw_overlay(
    frame: &mut Frame<'_>,
    title: &'static str,
    text: Vec<Line<'static>>,
    width_percent: u16,
    height: u16,
) {
    let area = centered_rect(width_percent, height, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false })
            .block(Block::default().title(title).borders(Borders::ALL)),
        area,
    );
}

pub(super) fn centered_rect(width_percent: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(height.min(area.height)),
            Constraint::Min(0),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_percent) / 2),
            Constraint::Percentage(width_percent),
            Constraint::Percentage((100 - width_percent) / 2),
        ])
        .split(vertical[1])[1]
}
