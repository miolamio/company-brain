import { describe, expect, it } from "vitest"
import { db } from "@repo/db"
import { mcpOAuthState } from "@repo/db/schema/brain/mcp"
import { createTestD1 } from "../../../db/test-d1"
import { authorizationUrlIsSafe, recordConnectApproval } from "./connect"

const PROVIDER = "https://provider.example/oauth/authorize?x=1"

async function seed(env: Env, token: string) {
	await db(env)
		.insert(mcpOAuthState)
		.values({
			stateToken: token,
			orgId: "org_1",
			userId: "user_1",
			serverSlug: "linear",
			serverUrl: "https://mcp.example/mcp",
			context: { slack: { teamId: "T", channel: "C", threadTs: "1", slackUserId: "U" } },
			expiresAt: new Date(Date.now() + 60_000),
		})
}

const args = (env: Env) => ({
	env,
	userId: "user_1",
	callbackOrigin: "https://brain.example/",
})

async function rows(env: Env) {
	return db(env).select().from(mcpOAuthState)
}

describe("recordConnectApproval", () => {
	it("stores the approver and provider URL, returning our /authorize link", async () => {
		const env = { DB: createTestD1() } as unknown as Env
		await seed(env, "tok1")
		const res = await recordConnectApproval(args(env), {
			ok: true,
			authUrl: PROVIDER,
			stateToken: "tok1",
		})
		expect(res).toMatchObject({ ok: true, stateToken: "tok1" })
		expect(res.ok && "authUrl" in res && res.authUrl).toBe(
			"https://brain.example/brain/mcp-connections/authorize?state=tok1",
		)
		const [row] = await rows(env)
		expect(row?.context?.approval).toEqual({
			userId: "user_1",
			authorizationUrl: PROVIDER,
		})
		expect(row?.context?.slack?.channel).toBe("C")
	})

	it("passes errors and already-authorized results through", async () => {
		const env = { DB: createTestD1() } as unknown as Env
		const err = { ok: false as const, error: "nope", status: 400 }
		expect(await recordConnectApproval(args(env), err)).toBe(err)
		const done = { ok: true as const, alreadyAuthorized: true as const }
		expect(await recordConnectApproval(args(env), done)).toBe(done)
	})

	it("rejects a non-https authorization URL and drops the state", async () => {
		const env = { DB: createTestD1() } as unknown as Env
		for (const bad of [
			"javascript:alert(1)",
			"http://provider.example/auth",
			"data:text/html,x",
			"not a url",
		]) {
			await seed(env, "bad")
			const res = await recordConnectApproval(args(env), {
				ok: true,
				authUrl: bad,
				stateToken: "bad",
			})
			expect(res.ok).toBe(false)
			expect(await rows(env)).toHaveLength(0)
		}
	})
})

describe("authorizationUrlIsSafe", () => {
	it("allows http only for loopback", () => {
		expect(authorizationUrlIsSafe("https://a.example/x")).toBe(true)
		expect(authorizationUrlIsSafe("http://localhost:8787/x")).toBe(true)
		expect(authorizationUrlIsSafe("http://127.0.0.1/x")).toBe(true)
		expect(authorizationUrlIsSafe("http://[::1]:3000/x")).toBe(true)
		expect(authorizationUrlIsSafe("http://localhost.evil.example/x")).toBe(false)
		expect(authorizationUrlIsSafe("ftp://a.example")).toBe(false)
	})
})
