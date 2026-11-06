import { afterEach, describe, expect, it } from "vitest"
import { Hono } from "hono"
import { db } from "@repo/db"
import { organization } from "@repo/db/schema/auth"
import { createTestD1 } from "../db/test-d1"
import type { AppContext } from "@/types"
import { authRoutes, safeReturnTo } from "./routes"

function kvStub() {
	const store = new Map<string, string>()
	return {
		store,
		put: async (k: string, v: string) => void store.set(k, v),
		get: async (k: string) => store.get(k) ?? null,
		delete: async (k: string) => void store.delete(k),
	}
}

function makeEnv() {
	const kv = kvStub()
	const env = {
		DB: createTestD1(),
		BRAIN_KV: kv,
		ENCRYPTION_SECRET: "test-secret",
		PUBLIC_URL: "https://brain.example",
		SLACK_CLIENT_ID: "cid",
		SLACK_CLIENT_SECRET: "csecret",
		SLACK_SIGNING_SECRET: "sign",
	} as unknown as Env
	const app = new Hono<AppContext>()
	app.route("/auth", authRoutes)
	const request = (path: string, cookie?: string) =>
		app.request(
			`https://brain.example${path}`,
			{ headers: cookie ? { cookie } : {} },
			env,
		)
	return { env, kv, request }
}

const realFetch = globalThis.fetch
afterEach(() => {
	globalThis.fetch = realFetch
})

function b64(obj: unknown) {
	return btoa(JSON.stringify(obj)).replace(/=+$/, "")
}

function stubSlack(nonceFor: (n: string) => string, nonce: () => string) {
	globalThis.fetch = (async (input: RequestInfo | URL) => {
		const url = String(input)
		if (url.endsWith("openid.connect.token")) {
			return Response.json({
				ok: true,
				access_token: "tok",
				id_token: `h.${b64({ nonce: nonceFor(nonce()) })}.s`,
			})
		}
		return Response.json({
			ok: true,
			email: "Ann@Example.com",
			name: "Ann",
			"https://slack.com/team_id": "T1",
			"https://slack.com/team_name": "Acme",
		})
	}) as typeof fetch
}

async function startLogin(
	request: ReturnType<typeof makeEnv>["request"],
	path = "/auth/slack/login",
) {
	const res = await request(path)
	const state = new URL(res.headers.get("location") ?? "").searchParams.get("state")
	const nonce = new URL(res.headers.get("location") ?? "").searchParams.get("nonce")
	const setCookie = res.headers.get("set-cookie") ?? ""
	return { res, state: state ?? "", nonce: nonce ?? "", setCookie }
}

describe("Slack sign-in state binding", () => {
	it("sets an HttpOnly, path-scoped state cookie at login", async () => {
		const { request } = makeEnv()
		const { setCookie, state } = await startLogin(request)
		expect(setCookie).toContain(`slack_login_state=${state}`)
		expect(setCookie).toContain("HttpOnly")
		expect(setCookie).toContain("Secure")
		expect(setCookie).toContain("Path=/auth/slack")
		expect(setCookie).toContain("SameSite=Lax")
	})

	it("rejects a callback without the cookie, and keeps the state usable", async () => {
		const { request, kv } = makeEnv()
		const { state } = await startLogin(request)
		const res = await request(`/auth/slack/callback?code=c&state=${state}`)
		expect(res.status).toBe(400)
		expect(res.headers.get("set-cookie") ?? "").not.toContain("brain_session")
		expect(kv.store.has(`auth:slack:${state}`)).toBe(true)
	})

	it("rejects a cookie that differs from the state", async () => {
		const { request } = makeEnv()
		const { state } = await startLogin(request)
		const res = await request(
			`/auth/slack/callback?code=c&state=${state}`,
			"slack_login_state=someone-else",
		)
		expect(res.status).toBe(400)
	})

	it("rejects an id_token whose nonce does not match", async () => {
		const { request } = makeEnv()
		const { state } = await startLogin(request)
		stubSlack(() => "wrong", () => "")
		const res = await request(
			`/auth/slack/callback?code=c&state=${state}`,
			`slack_login_state=${state}`,
		)
		expect(res.status).toBe(400)
		expect(res.headers.get("set-cookie") ?? "").not.toContain("brain_session")
	})

	it("rejects an id_token with no nonce", async () => {
		const { request } = makeEnv()
		const { state } = await startLogin(request)
		globalThis.fetch = (async () =>
			Response.json({ ok: true, access_token: "tok" })) as typeof fetch
		const res = await request(
			`/auth/slack/callback?code=c&state=${state}`,
			`slack_login_state=${state}`,
		)
		expect(res.status).toBe(400)
	})

	it("signs in once, clears cookie and KV, and refuses a replay", async () => {
		const { env, request, kv } = makeEnv()
		const { state, nonce } = await startLogin(request)
		stubSlack((n) => n, () => nonce)
		const url = `/auth/slack/callback?code=c&state=${state}`
		const res = await request(url, `slack_login_state=${state}`)
		expect(res.status).toBe(302)
		const cookies = res.headers.get("set-cookie") ?? ""
		expect(cookies).toContain("brain_session=")
		expect(cookies).toMatch(/slack_login_state=;/)
		expect(kv.store.has(`auth:slack:${state}`)).toBe(false)
		expect(await db(env).select().from(organization)).toHaveLength(1)

		const replay = await request(url, `slack_login_state=${state}`)
		expect(replay.status).toBe(400)
	})

	it("returns to a stored MCP connection path after sign-in", async () => {
		const { request } = makeEnv()
		const target = "/brain/mcp-connections/authorize?state=abc"
		const { state, nonce } = await startLogin(
			request,
			`/auth/slack/login?return_to=${encodeURIComponent(target)}`,
		)
		stubSlack((n) => n, () => nonce)
		const res = await request(
			`/auth/slack/callback?code=c&state=${state}`,
			`slack_login_state=${state}`,
		)
		expect(res.status).toBe(302)
		// A fresh deployment still goes to /setup first; installed ones return.
		expect(["/setup", target]).toContain(res.headers.get("location"))
	})
})

describe("safeReturnTo", () => {
	it("accepts only MCP connection paths", () => {
		expect(safeReturnTo("/brain/mcp-connections/authorize?state=x")).toBe(
			"/brain/mcp-connections/authorize?state=x",
		)
		for (const bad of [
			"https://evil.example/brain/mcp-connections/x",
			"//evil.example",
			"/brain/mcp-connections//evil.example",
			"/other",
			"/brain/mcp-connections/\\evil",
			"/brain/mcp-connections/../../x",
			"",
			undefined,
		]) {
			expect(safeReturnTo(bad as string)).toBeNull()
		}
	})
})
