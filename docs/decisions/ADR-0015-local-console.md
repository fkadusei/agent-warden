# ADR-0015: A local console, and what it is allowed to do

- **Status:** Accepted
- **Date:** 2026-09-16
- **Related:** threats W6 (approval bypass), W7 (Warden bypass); ADR-0009 (approval
  receipts); ADR-0011 (transport); Phase 5 step 5.5

## Context

Warden's behaviour is currently visible only as terminal output. Watching a decision get
made, seeing a call wait for approval, approving it, and checking the log are four
commands in two terminals. For a demo, and for anyone judging the project in five
minutes, that is a poor showing of work that is otherwise finished.

A console raises an obvious question: a web page that can approve a payment is itself a
capability. Getting that wrong would undo the control ADR-0009 exists to provide.

## Decision

1. **`warden console` is a local operator tool, not a service.** It binds to loopback
   only. It is not multi-user, has no accounts, and is not intended to be exposed.
2. **Approvals are opt-in.** Without `--key`, the console is read-only: receipts and
   verification, no approve or reject. Approving requires the operator to pass an
   approver key, exactly as `warden approve` does.
3. **It reuses the approver API, never a shortcut.** Pending calls come from
   `approverapi.Client.List`, and approvals go through `Sign` and `Submit`. `Sign`
   verifies the shown arguments against the decision's commitment and computes the call
   digest itself, so a compromised Warden cannot get an approver to sign a different
   call. The console adds no second signing path.
4. **A startup token guards the local surface.** The console prints a URL containing a
   random token and requires it on every API call. Without it, any process or page on the
   machine could drive an approval. This is a guard against local mistakes, not an
   authentication system.
5. **It does not open the receipt store.** `serve` holds it with a single connection, and
   a second opener would contend with the running gateway and run schema setup against a
   live database. The console reads receipts from an exported log the operator names.

## Consequences

- The demo becomes watchable, and the approval step is visible as a decision a person
  makes rather than a command someone typed.
- The approver key lives in the console process's memory for as long as it runs. That is
  the same exposure as `warden approve`, held open for longer; the README and `--help`
  say so.
- Anyone with access to the machine and the token can approve. On a shared machine, do
  not run the console with a key.
- The console shows a snapshot of an exported log rather than a live tail. Re-exporting
  is one command, and it keeps the running gateway's store untouched — checked: `warden
  export` works while `serve` is running, so the view refreshes without stopping Warden.
- Before Warden's first checkpoint there is no anchor file. That is reported as "the log
  verifies; no checkpoint has been written yet, so truncation cannot be detected", the
  same caveat `warden-verify` prints, rather than as a verification failure.
