//! bwrap discovery + argv construction (pure; unit-testable without bwrap).
//!
//! Phase 3 / spec §3 + §5: locate the system `bwrap` binary (absent →
//! `NetworkPolicy::Proxied` falls back to `Error::Unsupported`) and build the
//! argv that establishes the mount + user + pid + net namespaces under which
//! the helper's inner stage runs.
//!
//! The argv builder is pure (no syscalls, no env access) so it can be unit
//! tested on any Linux host (and via `cargo build` on macOS — the module is
//! cfg-gated). It deliberately does NOT validate paths, deduplicate entries,
//! or peek at the filesystem — those are caller concerns.

#![cfg(target_os = "linux")]

use std::path::PathBuf;

/// First `bwrap` on `PATH`, or `None`. Spec §3: system-only — no vendoring,
/// no C-build fallback; if this returns `None`, the Proxied path must
/// degrade to `Error::Unsupported(LinuxSeccomp)`.
#[allow(dead_code)] // wired by Task 7 (run() Linux Proxied integration)
pub(crate) fn find_bwrap() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("bwrap"))
            .find(|p| p.is_file())
    })
}

/// Build the bwrap argv that runs `inner_argv` under a fresh mount + user + pid
/// + net namespace (spec §5: read-everywhere root, re-enable writable roots,
/// re-protect read-only carveouts; namespaces give the bwrap mount-FS view +
/// the hard netns wall). `inner_argv` is the command bwrap runs, typically
/// `[helper_exe, real_program, real_args...]` — bwrap appends nothing.
///
/// Working directory: the outer helper is spawned with `current_dir = cmd.cwd`
/// (by `spawn_and_capture`), and bwrap inherits/preserves that cwd for the
/// inner command — so no `--chdir` is needed here. If a future change shows
/// the target's cwd isn't `cmd.cwd`, add `--chdir <cwd>` (the cwd is readable
/// via `--ro-bind / /`).
///
/// Mount layering (spec §5): whole FS read-only → writable_roots re-enable
/// writes → read_only_subpaths re-protect inside a writable root. bwrap
/// applies mounts in argv order, so writable roots are sorted shallow-to-deep
/// to keep deeper rules layered on top; read-only carveouts come last so they
/// always override the writable bind they sit inside.
#[allow(dead_code)] // wired by Task 6 (helper::run_if_invoked ProxiedOuter dispatch)
pub(crate) fn build_bwrap_argv(
    writable_roots: &[PathBuf],
    read_only_subpaths: &[PathBuf],
    inner_argv: &[String],
) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    a.push("--new-session".into());
    a.push("--die-with-parent".into());
    // FS view: whole FS read-only, then re-enable writes, then re-protect subpaths.
    a.push("--ro-bind".into());
    a.push("/".into());
    a.push("/".into());
    a.push("--dev".into());
    a.push("/dev".into());
    a.push("--proc".into());
    a.push("/proc".into());
    // Writable roots, shallow → deep, so deeper rules layer on top.
    let mut roots = writable_roots.to_vec();
    roots.sort_by_key(|p| p.components().count());
    for r in &roots {
        let s = r.to_string_lossy().into_owned();
        a.push("--bind".into());
        a.push(s.clone());
        a.push(s);
    }
    // Read-only carveouts inside writable roots (bwrap CAN express this —
    // spec §5: this closes the Linux gap that the Landlock path can't).
    for ro in read_only_subpaths {
        let s = ro.to_string_lossy().into_owned();
        a.push("--ro-bind".into());
        a.push(s.clone());
        a.push(s);
    }
    // Namespaces: user (unprivileged) + pid (target=pid1, kernel-reaps the
    // forked bridge — spec §7) + net (the hard wall — spec §1/§4).
    a.push("--unshare-user".into());
    a.push("--unshare-pid".into());
    a.push("--unshare-net".into());
    a.push("--".into());
    a.extend(inner_argv.iter().cloned());
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_has_ro_root_writable_bind_and_unshare_net() {
        let argv = build_bwrap_argv(
            &[PathBuf::from("/ws")],
            &[PathBuf::from("/ws/secret")],
            &[
                "/inner".into(),
                "--mode=proxied-inner".into(),
                "--".into(),
                "/bin/true".into(),
            ],
        );
        let s = argv.join(" ");
        assert!(s.contains("--ro-bind / /"));
        assert!(s.contains("--bind /ws /ws"));
        assert!(s.contains("--ro-bind /ws/secret /ws/secret"));
        assert!(s.contains("--unshare-net"));
        assert!(s.contains("--unshare-pid"));
        assert!(s.contains("--unshare-user"));
        assert!(s.contains("--proc /proc"));
        assert!(s.contains("--dev /dev"));
        // inner command after `--`
        let dd = argv.iter().position(|x| x == "--").unwrap();
        assert_eq!(argv[dd + 1], "/inner");
        assert_eq!(argv[dd + 2], "--mode=proxied-inner");
    }

    #[test]
    fn writable_roots_are_sorted_shallow_to_deep() {
        // Deeper writable root must come AFTER the shallow one so the deeper
        // mount layers on top in bwrap's apply-in-order semantics.
        let argv = build_bwrap_argv(
            &[
                PathBuf::from("/a/b/c"),
                PathBuf::from("/a"),
                PathBuf::from("/a/b"),
            ],
            &[],
            &["/inner".into()],
        );
        // Find positions of each `--bind <p> <p>` triple.
        let pos = |needle: &str| {
            argv.iter()
                .position(|w| w == needle)
                .unwrap_or_else(|| panic!("missing {needle}"))
        };
        assert!(pos("/a") < pos("/a/b"));
        assert!(pos("/a/b") < pos("/a/b/c"));
    }

    #[test]
    fn ro_carveouts_emitted_after_writable_binds() {
        let argv = build_bwrap_argv(
            &[PathBuf::from("/ws")],
            &[PathBuf::from("/ws/secret")],
            &["/inner".into()],
        );
        // Find the index of the writable bind triple for /ws and the ro-bind
        // triple for /ws/secret; the ro-bind must come AFTER so it wins.
        let writable_idx = argv
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == "/ws" && w[2] == "/ws")
            .expect("missing writable /ws bind");
        let ro_idx = argv
            .windows(3)
            .position(|w| w[0] == "--ro-bind" && w[1] == "/ws/secret" && w[2] == "/ws/secret")
            .expect("missing ro-bind /ws/secret");
        assert!(ro_idx > writable_idx);
    }

    #[test]
    fn no_extra_flags_when_no_roots() {
        let argv = build_bwrap_argv(&[], &[], &["/bin/true".into()]);
        // Must still set the safety flags + the three namespaces + ro-root.
        let s = argv.join(" ");
        assert!(s.contains("--new-session"));
        assert!(s.contains("--die-with-parent"));
        assert!(s.contains("--ro-bind / /"));
        assert!(s.contains("--unshare-user"));
        assert!(s.contains("--unshare-pid"));
        assert!(s.contains("--unshare-net"));
        // Final token = the inner program after `--`.
        let dd = argv.iter().position(|x| x == "--").unwrap();
        assert_eq!(argv[dd + 1], "/bin/true");
    }

    #[test]
    fn find_bwrap_returns_path_or_none() {
        // Smoke: doesn't panic; result depends on whether bwrap is on PATH.
        let _ = find_bwrap();
    }
}
