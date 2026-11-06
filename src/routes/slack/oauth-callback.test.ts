import { Hono } from "hono"
import { describe, expect, it } from "vitest"
import type { AppContext } from "@/types"
import { slackRoutes } from "./index"

function run(session: { id: string } | null, orgId = "org_a") {
	const store = new Map([
		["slack:oauth:st1", JSON.stringify({ orgId: "org_a", userId: "u_admin" })],
	])
	const env = {
		BRAIN_KV: {
			get: async (k: string) => store.get(k) ?? null,
			delete: async (k: string) => void store.delete(k),
		},
	} as unknown as Env
	const app = new Hono<AppContext>()
	app.use(async (c, next) => {
		c.set("user", session as never)
		c.set("org", session ? ({ id: orgId } as never) : null)
		await next()
	})
	app.route("/", slackRoutes)
	return { store, res: app.request("/oauth/callback?code=x&state=st1", {}, env) }
}

describe("Slack install callback", () => {
	it("refuses a signed-out browser, another user or another org, keeping the state", async () => {
		for (const [session, org] of [
			[null, "org_a"],
			[{ id: "u_other" }, "org_a"],
			[{ id: "u_admin" }, "org_b"],
		] as const) {
			const { res, store } = run(session, org)
			expect((await res).status).toBe(403)
			expect(store.has("slack:oauth:st1")).toBe(true)
		}
	})
})
