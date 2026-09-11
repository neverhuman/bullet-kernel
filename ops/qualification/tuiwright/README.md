# Local Tuiwright component qualification

This standalone Rust workspace executes actual Tuiwright `Page` sessions on
xbabe2. It is separate from Kernel's hosted portable workspace and does not add
tests or dependencies to that workspace. All twelve selected identities must
complete successfully. Missing prerequisites, changed binaries, failed cases,
lost custody, and incomplete execution never become success.
An independent 180-second watchdog holds a pidfd for the harness itself. If a
driver or cleanup operation stops progressing, deadline termination leaves
incomplete, nonpassing observations. Parent-fixture termination polls for at
most five seconds; its diagnostic pipe is read without blocking.

The four product cases launch the selected Bullet executable against private
synthetic credentials and a bounded loopback HTTP fixture. They cover six
concurrent clients while HTTP responses are withheld, six while credential
storage is locked, six without credentials, and 401/403 owner revocation and
recovery. Actual keys, help, navigation, resizing, independent detach and
terminal restoration are exercised. The fixture rejects mutations and
unexpected reads. It is not a production daemon or provider transaction.

Eight harness cases check nonce rejection, failure after Page creation, failed
exec, exit 19, ignored detach followed by confirmed forced termination, incomplete
terminal restoration, parent death, and normal detach. The partial-restoration
parent-death child fixture blocks SIGHUP after exec to isolate the required
SIGKILL from PTY master-close hangup. The owner verifies the child signal mask
before killing its parent; the parent and adopted child must both be observed and
reaped. The partial-restoration fixture changes VERASE while restoring the
other settings; checking only the
three usual mode fields cannot pass that case.

## Reproduction

First admit the exact Cargo/Rust toolchain, private build target, dependencies,
source freeze and process custody under the governing proof policy. Build in
this workspace with `cargo build --locked --release`, using a private absolute
`CARGO_TARGET_DIR`. Retain the build output, resolved lockfile, tool hashes and
source-to-binary binding. Serialize this workload with other heavy proofs.

Run the resulting harness with explicit canonical paths and the selected
Bullet executable's SHA-256:

```sh
/absolute/private-target/release/bullet-tuiwright-qualification --list
/absolute/private-target/release/bullet-tuiwright-qualification component \
  --bullet /absolute/canonical/bullet \
  --sha256 THE_EXACT_64_CHARACTER_SHA256 \
  --output /absolute/private-parent/new-observation
```

The output directory must not exist. The harness creates it with mode 0700 and
uses create-once mode-0600 artifacts. It records selected/completed identities,
failures, action and screen observations, monotonic timing, process exits,
reaping, source hashes observed at runtime, and executable hashes. It checks
the Bullet hash again after execution. The required external review must still
bind the built executable to the frozen source; runtime source hashes alone
cannot establish that binding.

`CI` or `GITHUB_ACTIONS` being present refuses execution, including values such
as `false`. Component execution requires Linux and the exact xbabe2 hostname.
The `installed` mode exits 78 with
`SIGNED_INSTALLED_PACKAGE_ADMISSION_REQUIRED`: the signed package and
authenticated installation consumers are not yet available. No production
credentials are read by that path. An installed executable used with synthetic
credentials is still component evidence.

## Process and terminal custody

Pinned Tuiwright has no public PID or wait API. A private launcher establishes
a bounded Unix-socket nonce and peer-identity handshake before directly executing
Bullet. The harness records the new direct child and opens its pidfd before
allowing exec. Parent-death SIGKILL and a parent identity recheck prevent the
launcher from continuing after its owner disappears. The launcher creates no
descendant execution tree.

The harness observes exit using `waitid(P_PIDFD, WEXITED | WNOWAIT)` before
dropping Page. This leaves the zombie reserved so the PID cannot recycle before
Tuiwright's private Child cleanup. Pinned portable-pty may reap inside that
cleanup. Only after this exact exit observation and Page drop may ECHILD mean
that cleanup already reaped the child. Never reap before Page drop. Failure
cleanup uses the exact pidfd and follows the same ordering. Preconstruction
failures retain a guard over the newly created direct children while the exec
permission remains withheld.

Terminal acceptance compares input, output, control and local modes, line
discipline, all public Linux special controls, and input/output speeds. A
failure to read terminal state remains a failure even if process cleanup
succeeds. This is cooperative Linux component custody, not hostile multi-user
containment or installed platform certification.

The observations are not raw terminal transcripts or continuous recordings.
Tuiwright's built-in trace reports output byte counts, so it is not used as a
transcript. Startup timing runs from permission to execute to the observed
screen, with spawn/launcher overhead outside that interval. These observations
do not certify the product's initial-paint or key-to-paint percentile targets.
No GIF or public media proof is emitted.

## Pinned upstream subjects and notices

Tuiwright 0.1.0 comes from
[`neverhuman/jankurai` revision 5e85a4de](https://github.com/neverhuman/jankurai/tree/5e85a4de2ce59a8d1fc7865520665af58e9e6727/crates/tuiwright).
Its crate tree is `c7dce342986889287d4bd0da48ce54973ebe8148`.
The MIT notice is retained byte-for-byte in [LICENSE-JANKURAI](LICENSE-JANKURAI).
The manifest forces portable-pty 0.9.0, whose private Child implementation was
reviewed. The Cargo lockfile pins all resolved transitive dependencies.

The embedded JetBrains Mono Regular font reports version 2.305 and SHA-256
`e6fd0d7e91550b3ed2b735d4312474362c4716edc4fc0577a0f61ed782d5aed1`.
Those bytes also match the font at
[`JetBrains/JetBrainsMono` revision 19371302](https://github.com/JetBrains/JetBrainsMono/tree/19371302b95d218af43299bce79ddbddd0bc364d/fonts/ttf).
The exact [upstream OFL notice](https://github.com/JetBrains/JetBrainsMono/blob/19371302b95d218af43299bce79ddbddd0bc364d/OFL.txt)
is retained as [LICENSE-JETBRAINS-MONO](LICENSE-JETBRAINS-MONO), SHA-256
`a76abf002c49097d146e86740a3105a5d00450b1592e820a1109a8c5680cd697`.
Retain both notices when distributing this harness with its embedded dependencies.
