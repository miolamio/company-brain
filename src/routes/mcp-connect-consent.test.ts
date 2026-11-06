import { Hono } from "hono"
import { describe, expect, it } from "vitest"
import { db } from "@repo/db"
import { mcpOAuthState } from "@repo/db/schema/brain/mcp"
import { createTestD1 } from "../db/test-d1"
import type { AppContext } from "@/types"
import { canApproveConnect } from "./mcp-connect-policy"
import { brainMcpConnectionsRoutes } from "./mcp-connections"

const ORG = "org_acme"
const OWNER = "user_owner"
const OTHER = "user_other"
const PROVIDER_URL = "https://provider.example/oauth/authorize?client_id=abc"

const approval = { userId: OWNER, authorizationUrl: PROVIDER_URL }
const slackContext = {
	teamId: "T1",
	channel: "C1",
	threadTs: "1700000000.0",
	slackUserId: "U1",
}
const personal = { orgId: ORG, userId: OWNER, context: { approval } }
const shared = { orgId: ORG, userId: null, context: { approval } }
const owner = { userId: OWNER, orgId: ORG, canManageShared: false }

describe("canApproveConnect", () => {
	it("lets the account that started a personal flow approve it", () => {
		expect(canApproveConnect(personal, owner)).toBe(true)
	})

	it("rejects another account, a signed-out session and a missing approval", () => {
		expect(canApproveConnect(personal, { ...owner, userId: OTHER })).toBe(false)
		expect(
			canApproveConnect(personal, { ...owner, userId: null, orgId: null }),
		).toBe(false)
		expect(canApproveConnect({ ...personal, context: null }, owner)).toBe(false)
	})

	it("rejects a session in another org", () => {
		expect(canApproveConnect(personal, { ...owner, orgId: "org_other" })).toBe(
			false,
		)
	})

	it("needs the initiator to still be an admin for a shared flow", () => {
		expect(canApproveConnect(shared, { ...owner, canManageShared: true })).toBe(
			true,
		)
		expect(canApproveConnect(shared, owner)).toBe(false)
		expect(
			canApproveConnect(shared, {
				userId: OTHER,
				orgId: ORG,
				canManageShared: true,
			}),
		).toBe(false)
	})

	it("applies to Slack-initiated flows too", () => {
		const slack = { ...personal, context: { approval, slack: slackContext } }
		expect(canApproveConnect(slack, owner)).toBe(true)
		expect(
			canApproveConnect(slack, { ...owner, userId: null, orgId: null }),
		).toBe(false)
	})
})

function appFor(session: { id: string } | null, env: Env) {
	const app = new Hono<AppContext>()
	app.use(async (c, next) => {
		c.set("user", session as never)
		c.set("org", session ? ({ id: ORG } as never) : null)
		c.set("memberRole", null)
		await next()
	})
	app.route("/", brainMcpConnectionsRoutes)
	return (path: string) => app.request(path, {}, env)
}

async function seed(env: Env, token: string, over: Record<string, unknown> = {}) {
	await db(env)
		.insert(mcpOAuthState)
		.values({
			stateToken: token,
			orgId: ORG,
			userId: OWNER,
			serverSlug: "linear",
			serverUrl: "https://mcp.example/mcp",
			context: { approval },
			expiresAt: new Date(Date.now() + 60_000),
			...over,
		})
}

describe("GET /authorize", () => {
	const env = { DB: createTestD1() } as unknown as Env

	it("sends the initiating account on to the stored provider URL", async () => {
		await seed(env, "st_ok")
		const res = await appFor({ id: OWNER }, env)("/authorize?state=st_ok")
		expect(res.status).toBe(303)
		expect(res.headers.get("location")).toBe(PROVIDER_URL)
		expect(res.headers.get("cache-control")).toBe("no-store")
	})

	it("asks for sign-in when there is no session, without redirecting", async () => {
		await seed(env, "st_anon")
		const res = await appFor(null, env)("/authorize?state=st_anon")
		expect(res.status).toBe(401)
		expect(res.headers.get("location")).toBeNull()
		expect(await res.text()).toContain("/auth/slack/login")
	})

	it("refuses a different signed-in account", async () => {
		await seed(env, "st_other")
		const res = await appFor({ id: OTHER }, env)("/authorize?state=st_other")
		expect(res.status).toBe(403)
		expect(res.headers.get("location")).toBeNull()
	})

	it("rejects unknown, missing and expired state", async () => {
		await seed(env, "st_old", { expiresAt: new Date(Date.now() - 1000) })
		const get = appFor({ id: OWNER }, env)
		expect((await get("/authorize?state=nope")).status).toBe(400)
		expect((await get("/authorize")).status).toBe(400)
		expect((await get("/authorize?state=st_old")).status).toBe(400)
	})

	it("ignores any URL supplied in the query", async () => {
		await seed(env, "st_q")
		const res = await appFor({ id: OWNER }, env)(
			`/authorize?state=st_q&authorizationUrl=${encodeURIComponent("https://evil.example")}&redirect=https://evil.example`,
		)
		expect(res.headers.get("location")).toBe(PROVIDER_URL)
	})
})

describe("GET /callback", () => {
	const env = { DB: createTestD1() } as unknown as Env

	it("rejects a signed-out callback and keeps the state for the real user", async () => {
		await seed(env, "cb_anon")
		const res = await appFor(null, env)("/callback?code=x&state=cb_anon")
		expect(res.status).toBe(401)
		expect(res.headers.get("cache-control")).toBe("no-store")
		const rows = await db(env).select().from(mcpOAuthState)
		expect(rows.some((r) => r.stateToken === "cb_anon")).toBe(true)
	})

	it("rejects another account, including for Slack-initiated flows", async () => {
		await seed(env, "cb_slack", { context: { approval, slack: slackContext } })
		const res = await appFor({ id: OTHER }, env)("/callback?code=x&state=cb_slack")
		expect(res.status).toBe(403)
	})

	it("rejects an unknown or already-consumed state", async () => {
		const res = await appFor({ id: OWNER }, env)("/callback?code=x&state=gone")
		expect(res.status).toBe(400)
	})
})
