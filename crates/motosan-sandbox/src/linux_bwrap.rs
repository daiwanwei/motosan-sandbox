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

use std::io::{Error as IoError, ErrorKind};
use std::path::PathBuf;

/// Hard cap on total deny-read matches (mirrors Codex's 8192).
const MAX_DENY_READ_GLOB_MATCHES: usize = 8192;

/// Expand deny-read globs against the host FS (the outer helper stage runs on
/// the host before entering bwrap) and return bwrap mask args: files get
/// `--ro-bind /dev/null <p>`, directories get `--tmpfs <p>`. Walks from each
/// glob's static prefix. Errors if matches exceed the cap (refuse, don't
/// partially mask).
#[allow(dead_code)] // wired by Task 7 (run() Linux Proxied integration)
pub(crate) fn expand_deny_read_masks(globs: &[String]) -> std::io::Result<Vec<String>> {
    use globset::Glob;
    use walkdir::WalkDir;

    let mut args = Vec::new();
    let mut count = 0usize;
    for g in globs {
        let matcher = Glob::new(g)
            .map_err(|e| IoError::new(ErrorKind::InvalidInput, format!("bad glob {g:?}: {e}")))?
            .compile_matcher();
        let root = static_prefix_dir(g);
        for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
            let p = entry.path();
            if !matcher.is_match(p) {
                continue;
            }
            count += 1;
            if count > MAX_DENY_READ_GLOB_MATCHES {
                return Err(IoError::other(format!(
                    "deny-read glob {g:?} matched >{MAX_DENY_READ_GLOB_MATCHES} paths"
                )));
            }
            let s = p.to_string_lossy().into_owned();
            if entry.file_type().is_dir() {
                args.push("--tmpfs".into());
                args.push(s);
            } else {
                args.push("--ro-bind".into());
                args.push("/dev/null".into());
                args.push(s);
            }
        }
    }
    Ok(args)
}

/// The non-wildcard leading directory of a glob, e.g. `/a/b/**` → `/a/b`,
/// `/a/*.pem` → `/a`. Falls back to `/` if there is no static prefix.
fn static_prefix_dir(glob: &str) -> PathBuf {
    let cut = glob.find(['*', '?']).unwrap_or(glob.len());
    let prefix = &glob[..cut];
    match prefix.rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from("/"),
    }
}

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

/// Build the bwrap argv that runs `inner_argv` under a fresh set of mount,
/// user, pid, and net namespaces. (Spec §5: read-everywhere root, re-enable
/// writable roots, re-protect read-only carveouts; the namespaces provide
/// the bwrap mount-FS view plus the hard netns wall.) `inner_argv` is the
/// command bwrap runs, typically `[helper_exe, real_program, real_args...]`;
/// bwrap appends nothing.
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
    deny_read_masks: &[String],
    inner_argv: &[String],
) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "--new-session".into(),
        "--die-with-parent".into(),
        // FS view: whole FS read-only, then re-enable writes, then re-protect subpaths.
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        "--dev".into(),
        "/dev".into(),
        "--proc".into(),
        "/proc".into(),
    ];
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
    // Deny-read masks LAST so they override the whole-FS ro-bind AND any
    // writable --bind above (bwrap applies mounts in argv order).
    a.extend(deny_read_masks.iter().cloned());
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
    fn expand_deny_read_masks_files_and_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/.env"), b"x").unwrap();
        std::fs::create_dir(root.join("secretdir")).unwrap();

        let globs = vec![
            format!("{}/**/.env", root.display()),
            format!("{}/secretdir", root.display()),
        ];
        let masks = expand_deny_read_masks(&globs).unwrap();
        let file = root.join("sub/.env").to_string_lossy().into_owned();
        let dir = root.join("secretdir").to_string_lossy().into_owned();
        // file → ro-bind /dev/null; dir → tmpfs
        assert!(masks
            .windows(3)
            .any(|w| w == ["--ro-bind", "/dev/null", &file]));
        assert!(masks.windows(2).any(|w| w == ["--tmpfs", &dir]));
    }

    #[test]
    fn build_bwrap_argv_emits_masks_after_writable_binds() {
        // 4th param is PRE-FORMED bwrap mask args (not bare paths).
        let argv = build_bwrap_argv(
            &[std::path::PathBuf::from("/ws")],
            &[],
            &["--tmpfs".to_string(), "/ws/secret".to_string()],
            &["/inner".to_string()],
        );
        let s = argv.join(" ");
        let writable_idx = s.find("--bind /ws /ws").unwrap();
        let mask_idx = s.find("--tmpfs /ws/secret").unwrap();
        assert!(
            mask_idx > writable_idx,
            "masks must come after writable binds"
        );
    }

    #[test]
    fn argv_has_ro_root_writable_bind_and_unshare_net() {
        let argv = build_bwrap_argv(
            &[PathBuf::from("/ws")],
            &[PathBuf::from("/ws/secret")],
            &[],
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
            &[],
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
        let argv = build_bwrap_argv(&[], &[], &[], &["/bin/true".into()]);
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
