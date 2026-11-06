# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Supermemory "Company Brain": a Slack teammate that remembers, answers, acts through MCP, runs code, and runs scheduled digests and research. It deploys as a single Cloudflare Worker, with a React setup and admin UI in `web/`.

## Commands

Use bun. This is a single package, and `web/` shares the root `package.json`. Scripts are in `package.json`. No linter, formatter or CI is configured, so `bun run check-types` is the main static check.

- **Tests:** `bun run test` (which is `bun test`), or `bun test src/db/migrations.test.ts` for one file and `bun test -t "<name>"` to filter by name. The whole suite passes. `bunfig.toml` preloads `test/workers-shim.ts` to stub `cloudflare:workers`.
- **Writing tests:** import `describe`, `expect`, `it` and `vi.fn` from `vitest`, which bun maps to its own runner and which keeps `tsc` happy. Bun has no `vi.mock`. Prefer testing pure functions without module mocks, and use `mock.module` from `bun:test` only when a module truly has to be replaced. `bun:test` has no type declarations in this project, so `check-types` fails on it. Plain `vitest run` cannot load this suite: it resolves neither `cloudflare:` imports nor the tsconfig path aliases.
- **Local run:** `cp .dev.vars.example .dev.vars`, fill in the keys, then `bun run dev`. For Slack to reach the machine, run a tunnel, set `PUBLIC_URL` to the tunnel URL, and create the Slack app from the tunnel's `/setup` page.
- **Schema changes:** edit `src/db/schema/`, then run `bun run db:generate`. This writes the `drizzle/` SQL and rebundles it into `src/db/migrations.generated.ts`. `src/db/migrations.test.ts` fails if the two drift apart. The worker applies pending migrations itself on its next request (`ensureMigrated`), using the same `d1_migrations` table as wrangler.

## Architecture

- **Request path:** `src/worker.ts` is a Hono app. Global middleware runs in order: `hydrateSecrets`, `rememberPublicUrl`, `configureFromEnv`, `ensureMigrated`, `sessionMiddleware`. Routes are `/setup`, `/auth`, `/brain` (the API the SPA calls), `/slack` and `/health`. Everything else falls through to the `ASSETS` binding, which serves `dist/web`. A new top-level server route must also be added to `run_worker_first` in `wrangler.jsonc`, or the SPA will receive the request.
- **Agent:** `CompanyBrainAgent` (`src/brain/turn/agent.ts`, `agent.impl.ts`) is an Agents SDK Durable Object, one per org. `src/brain/slack/` handles events and triage, `src/brain/turn/` holds the model loop, tool assembly and approvals, and `src/brain/tools/` holds MCP, sandbox, web and scheduling tools.
- **Models:** `src/brain/turn/brain-model.ts` builds an AI SDK model per provider. When a provider has no direct key but `OPENROUTER_API_KEY` is set, it routes through OpenRouter (`OPENROUTER_BASE_URL` overrides the endpoint) and model ids stay `vendor/model`. `providerForModelKey` in `src/setup/secrets.ts` infers the provider from the `MODEL_API_KEY` prefix. Cloudflare AI Gateway is optional.
- **Code execution has two separate paths:**
  - QuickJS (`src/brain/codemode/quickjs-executor.ts`) runs in-worker as an `Executor` for `@cloudflare/codemode`, and is where approval pauses happen.
  - The sandbox (`src/brain/tools/sandbox/`) is either a Cloudflare container or Daytona, chosen by `availability.ts`. Containers need Workers Paid, the commented `containers` block in `wrangler.jsonc`, and `CONTAINER_SANDBOX` set to `"on"`. Free-plan deployments need `DAYTONA_API_KEY`.
- **Memory:** the supermemory API (`src/memory/client.ts`), with read and write logic in `src/brain/memory/`. Reads are scoped by a permissions graph (`read-scope.ts`): a public channel reads the shared brain, a private channel adds its own memory, and a DM adds personal memory and the asker's private channels. Any change to memory reads must preserve this scoping.
- **Persistence:** D1 through drizzle for app data, `BRAIN_KV` for OAuth state plus the auto-generated `deployment:encryption-secret` and the learned `deployment:public-url`, and Durable Object SQLite for per-org turn state.
- **Compat layer:** `src/compat/` holds shims for code ported from the hosted monorepo. The root tsconfig maps `@/lib/brain/*` to `src/brain/*`, `@/lib/*` to `src/compat/lib/*`, `@repo/db` to `src/db`, and `@repo/lib/*` to `src/compat/repo-lib/*`, so check the tsconfig `paths` before searching for these imports as packages. The `web/` aliases are defined separately in `web/tsconfig.json`.

## Traps

- **Stale docs:** the top-level pages in `docs/` and `wrangler.reference.jsonc` describe the old monorepo (`apps/api/**`, Postgres/Hyperdrive, `wrangler.brain.jsonc`). Trust the code, and when you touch one of these pages, correct it in the same change, as `docs/README.md` requires.
- **Generated files:** change the source and regenerate `src/db/migrations.generated.ts` and `drizzle/` (`bun run db:generate`) and `worker-configuration.d.ts` (`wrangler types`).
- **Patched dependencies:** `@cloudflare/codemode` and `ai-gateway-provider` are pinned exactly, with patches in `patches/`. Upgrading either means redoing its patch.
- **`wrangler.jsonc` placeholders:** the D1 `database_id` and the KV `id` are placeholders that the Cloudflare deploy button rewrites, so keep them as they are in commits.
- **Environment variables:** `.dev.vars.example` lists the ones needed to run locally, and `env-supplement.d.ts` lists the full set. Only `SUPERMEMORY_API_KEY` and `MODEL_API_KEY` are required.
