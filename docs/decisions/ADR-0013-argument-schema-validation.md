# ADR-0013: Validate arguments against the pinned input schema

- **Status:** Accepted
- **Date:** 2026-09-15
- **Related:** threats W2, W5; ADR-0007 (policy); ADR-0012 (demo agent); Phase 2 steps
  2.2 and 2.7

## Context

Warden pins each tool's manifest, including its input schema (step 2.2), but until now
it did not check arguments against that schema. Policy saw whatever the agent sent.

A Phase 3 run with a real model (llama3.2:3b) showed the gap: the model called
`mail.send` with `body` as a JSON object where the pinned schema requires a string.
Warden allowed the call and the tool accepted it. That call carried nothing harmful,
but unchecked arguments can reach tools in shapes their authors never reviewed, and can
slip past policy conditions written for the documented types (a rule comparing
`context.args.to` assumes `to` is a string).

Checked on 2026-09-15: `github.com/google/jsonschema-go` v0.4.3, already in the module
graph through the MCP Go SDK, compiles a schema with `Schema.Resolve` and validates a
decoded JSON value with `Resolved.Validate`. With no `Loader` set, resolving a remote
`$ref` is an error.

## Decision

1. **Every call's arguments are validated against the pinned manifest's input schema,**
   after the pin check and before policy. Arguments must be a JSON object that the
   schema allows.
2. **Fail closed.** Arguments that do not match, and a schema that cannot be compiled,
   deny the call with the gateway rule `invalid_arguments` and a decision receipt.
   Nothing reaches policy or the tool.
3. **No network.** Only references inside the schema are followed; remote `$ref`s make
   the schema unusable, which denies the call.
4. **The reason goes to the agent, not the receipt.** The agent gets a bounded message
   (it sent the arguments, so this reveals nothing new); the receipt records the rule,
   as for every decision, and never the arguments themselves (ADR-0005).
5. Compiled schemas are cached by manifest digest, so a changed manifest can never reuse
   an old schema.

## Consequences

- Policy conditions can rely on argument types the tool's reviewed schema promises.
- A tool whose schema is permissive (`{"type": "object"}`) gets no extra protection;
  schema quality is part of the review when pinning.
- Calls that tools would have tolerated but whose schemas forbid (extra arguments under
  `additionalProperties: false`) are now denied. That is the intended strictness.
