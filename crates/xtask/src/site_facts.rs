//! T174 — the website's claims, checked against the repository (`cargo test -p xtask site_facts`).
//!
//! The page says what the program is, what it does not do and where it stands. Each sentence that states a
//! fact about the code is tied here to the thing that makes it true, so that when the code changes and the page
//! does not, a test fails instead of a visitor being told something that is no longer so. The page has no
//! script (a workflow checks that too), so nothing here can be a build step: it is a test.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn read(relative: &str) -> String {
        std::fs::read_to_string(root().join(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
    }

    fn page() -> String {
        read("site/index.html")
    }

    /// The text between `<tag ...>` and the matching close, for a tag that does not nest in itself here.
    fn blocks<'a>(html: &'a str, open: &str, close: &str) -> Vec<&'a str> {
        let mut found = Vec::new();
        let mut rest = html;
        while let Some(start) = rest.find(open) {
            let after = &rest[start..];
            let Some(end) = after.find(close) else { break };
            found.push(&after[..end + close.len()]);
            rest = &after[end + close.len()..];
        }
        found
    }

    fn text_of(fragment: &str) -> String {
        let mut out = String::new();
        let mut in_tag = false;
        for c in fragment.chars() {
            match c {
                '<' => in_tag = true,
                '>' => {
                    in_tag = false;
                    out.push(' ');
                }
                _ if !in_tag => out.push(c),
                _ => {}
            }
        }
        out.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    // ------------------------------------------------------------------ what the page says about the platform

    /// The oldest Windows the installer accepts is what the page says, in the words people know it by.
    #[test]
    fn the_platform_is_what_the_installer_manifest_says() {
        let manifest = read("installer/winget/DNetEngine.DNetEngine.installer.yaml");
        assert!(
            manifest.contains("MinimumOSVersion: 10.0.17763.0"),
            "1809 is build 17763"
        );
        assert!(manifest.contains("Architecture: x64"));
        let page = page();
        assert!(
            page.contains("Windows 10 (version 1809) or later"),
            "the oldest version is named"
        );
        assert!(page.contains("64-bit"), "the architecture is named");
        assert!(
            !page.contains("Windows 10 or later"),
            "the vague form is gone"
        );
    }

    // ------------------------------------------------------------------ the installer

    /// The installer is written (configuration, hooks, manifests, a release workflow) and has not been built
    /// or run on Windows. The page must say neither "not built" nor that there is nothing.
    #[test]
    fn the_installer_is_described_as_what_it_is() {
        for file in [
            "installer/hooks.nsh",
            "installer/tauri.installer.json",
            "installer/winget/DNetEngine.DNetEngine.installer.yaml",
            ".github/workflows/release.yml",
        ] {
            assert!(
                root().join(file).is_file(),
                "{file} is what the page's sentence rests on"
            );
        }
        let page = text_of(&page());
        assert!(!page.contains("No installer yet"), "{page}");
        assert!(
            !page.contains("Installer Not built"),
            "an installer is written"
        );
        assert!(
            page.contains("Installer written; not yet built or run on Windows"),
            "the page must say what is true of the installer"
        );
    }

    // ------------------------------------------------------------------ setting a server up

    #[test]
    fn setting_a_server_up_is_described_as_the_guide_it_now_is() {
        assert!(root().join("apps/dnet-tray/src/lib/guide.ts").is_file());
        assert!(root().join("crates/dnetd/src/server_setup.rs").is_file());
        let page = text_of(&page());
        assert!(
            !page.contains("no real provider connected"),
            "that row described the old plan"
        );
        assert!(
            !page.contains("stand-in"),
            "that row described the old plan"
        );
        assert!(page.contains("guide"), "the row names the guide");
        assert!(
            page.contains("never asks for a cloud password or key")
                || page.contains("asks for no cloud password or key")
        );
    }

    // ------------------------------------------------------------------ the map of parts

    /// The page says where the live map of parts can be seen; that changes the day the window shows it.
    #[test]
    fn the_map_of_parts_is_said_to_be_where_it_is() {
        let window_shows_it =
            read("apps/dnet-tray/src/views/Activity.svelte").contains("bridge.components()");
        let page = text_of(&page());
        if window_shows_it {
            assert!(
                !page.contains("not yet in the window"),
                "the window shows the map now"
            );
            assert!(
                page.contains("live map of every part"),
                "the row is still there"
            );
            assert!(page.contains("the window"), "and says the window has it");
        } else {
            assert!(page.contains("not yet in the window"));
        }
    }

    // ------------------------------------------------------------------ the three limits

    /// A limit is true only while the code is as it says. These tie each limit's wording to its cause.
    #[test]
    fn each_limit_is_said_exactly_while_its_cause_holds() {
        // Compared without regard to capitals: a sentence may begin with the phrase.
        let page = text_of(&page()).to_lowercase();

        // Rules by program: `dnet-etw` is a dependency of the service but nothing in the service calls it.
        let dnetd = std::fs::read_dir(root().join("crates/dnetd/src")).unwrap();
        let calls_etw = dnetd
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
            .any(|e| {
                std::fs::read_to_string(e.path())
                    .unwrap()
                    .contains("dnet_etw::")
            });
        if calls_etw {
            assert!(
                !page.contains("not yet connected to the service"),
                "the service now calls it; the limit changed"
            );
        } else {
            assert!(page.contains("built and tested, but not yet connected to the service"));
        }

        // Switching networks: no method has a recorded survival, so none is called better. The record is
        // data now (`evidence/survival.json`): a record whose runs all survived at the pinned commit is what
        // would make a method Tier 1.
        let evidence = read("crates/dnet-core/evidence/survival.json");
        let any_record = evidence.contains("\"method\"");
        if !any_record {
            assert!(page.contains("no method has yet been measured to keep an open transfer alive"));
        } else {
            assert!(
                !page.contains("no method has yet been measured"),
                "a measurement is recorded; say what it showed"
            );
        }

        // The kill switch: the operating-system guard is not built, and its task is still open.
        let tasks = read("specs/001-network-resilience-client/tasks.md");
        let guard_open = tasks.lines().any(|l| l.starts_with("- [ ] T161 "));
        if guard_open {
            assert!(page.contains("not built yet"), "the guard is an open task");
        }
    }

    /// Each limit says why it exists, what is being done and where it stands: nothing is only a confession.
    #[test]
    fn every_limit_says_why_what_is_being_done_and_where_it_stands() {
        let page = page();
        let limits = blocks(&page, "<li class=\"limit\"", "</li>");
        assert_eq!(
            limits.len(),
            3,
            "the three limits the page has always named"
        );
        for limit in limits {
            let text = text_of(limit);
            for label in ["Why", "Being done", "Where it stands"] {
                assert!(text.contains(label), "a limit has no \"{label}\": {text}");
            }
            assert!(limit.contains("<h3"), "a limit has a heading");
            assert!(
                limit.contains("data-state="),
                "a limit carries its state for the reader and the stylesheet"
            );
        }
    }

    // ------------------------------------------------------------------ where it stands

    /// Three visible groups, each with its count, and the counts are the rows.
    #[test]
    fn the_status_is_three_groups_whose_counts_are_their_rows() {
        let page = page();
        let groups = blocks(&page, "<section class=\"group\"", "</section>");
        assert_eq!(groups.len(), 3, "works, built and tested, not yet");
        let mut names = Vec::new();
        let mut total = 0;
        for group in groups {
            let name = group
                .split("data-group=\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .expect("data-group");
            names.push(name.to_owned());
            let rows = group.matches("<li>").count();
            let shown: usize = group
                .split("<span class=\"count\">")
                .nth(1)
                .and_then(|s| s.split("</span>").next())
                .and_then(|n| n.trim().parse().ok())
                .expect("a count");
            assert_eq!(shown, rows, "the count shown for {name} is not its rows");
            assert!(rows > 0, "{name} is empty");
            total += rows;
        }
        assert_eq!(names, ["works", "built", "not-yet"]);
        assert!(total >= 8, "{total}");
        // The line above the groups says the same totals.
        assert!(
            text_of(&page).contains(&format!("{total} parts")),
            "the summary line must state {total} parts"
        );
    }

    // ------------------------------------------------------------------ the footer

    #[test]
    fn the_footer_has_its_groups_and_every_document_it_links_exists() {
        let page = page();
        let footer = blocks(&page, "<footer", "</footer>")
            .pop()
            .expect("a footer");
        let text = text_of(footer);
        for heading in [
            "The project",
            "The documents",
            "Licence and notices",
            "The name",
        ] {
            assert!(text.contains(heading), "no \"{heading}\" in the footer");
        }
        assert!(text.contains("GPL-3.0-or-later"), "the licence is named");
        assert!(
            read("Cargo.toml").contains("license = \"GPL-3.0-or-later\"")
                || read("Cargo.toml").contains("GPL-3.0-or-later")
        );
        assert!(
            text.contains("Checked 2026-11-04"),
            "the date the page was last checked"
        );
        // Every link into this repository points at something that is there.
        let prefix = "https://github.com/nikhlgoel/dnet-engine/blob/master/";
        let mut linked = 0;
        for piece in page.split("href=\"").skip(1) {
            let href = piece.split('"').next().unwrap();
            if let Some(path) = href.strip_prefix(prefix) {
                linked += 1;
                assert!(
                    root().join(path).is_file(),
                    "the page links to {path}, which is not in the repository"
                );
            }
        }
        assert!(linked >= 5, "{linked} documents linked");
    }

    // ------------------------------------------------------------------ the page as a whole

    /// Every task and decision the page names exists.
    #[test]
    fn every_task_and_decision_named_exists() {
        let page = text_of(&page());
        let tasks = read("specs/001-network-resilience-client/tasks.md");
        let words: Vec<&str> = page
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .collect();
        for word in &words {
            if word.len() == 4
                && word.starts_with('T')
                && word[1..].chars().all(|c| c.is_ascii_digit())
            {
                assert!(
                    tasks.contains(&format!("] {word} ")),
                    "the page names {word}, which is not a task"
                );
            }
        }
        let mut named = 0;
        for word in &words {
            let word = word.trim_matches('-');
            if let Some(number) = word.strip_prefix("ADR-") {
                if number.len() == 4 && number.chars().all(|c| c.is_ascii_digit()) {
                    named += 1;
                    let found = std::fs::read_dir(root().join("docs/adr"))
                        .unwrap()
                        .filter_map(Result::ok)
                        .any(|e| {
                            e.file_name()
                                .to_string_lossy()
                                .starts_with(&format!("{number}-"))
                        });
                    assert!(found, "the page names ADR-{number}, which does not exist");
                }
            }
        }
        assert!(named >= 2, "the page names its decisions ({named} found)");
    }

    /// Fragment links resolve and identifiers are unique.
    #[test]
    fn anchors_resolve_and_ids_are_unique() {
        let page = page();
        let mut ids = Vec::new();
        for piece in page.split(" id=\"").skip(1) {
            ids.push(piece.split('"').next().unwrap().to_owned());
        }
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "an id is used twice");
        for piece in page.split("href=\"#").skip(1) {
            let id = piece.split('"').next().unwrap();
            assert!(ids.iter().any(|i| i == id), "href=#{id} points at nothing");
        }
    }

    /// The page keeps its promise: no script, no external load, no cookie.
    #[test]
    fn the_page_runs_nothing_and_loads_nothing_from_elsewhere() {
        let page = page();
        for forbidden in ["<script", "<iframe", "<object", "<embed", "document.cookie"] {
            assert!(!page.contains(forbidden), "{forbidden}");
        }
        for piece in page
            .split("<link")
            .skip(1)
            .chain(page.split("<img").skip(1))
        {
            let tag = piece.split('>').next().unwrap();
            assert!(
                !tag.contains("http://") && !tag.contains("https://"),
                "{tag}"
            );
        }
        let css = read("site/site.css");
        assert!(!css.contains("@import") && !css.contains("url(http"));
    }
}
