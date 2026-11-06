import { afterEach, describe, expect, it } from "vitest"
import type { CompanyBrainAgent } from "../turn/agent"
import {
	type BrainNodeMapping,
	NOT_FOUND_GRACE_MS,
	reconcileBrainMemoryNodeMappings,
} from "./tree"

const realFetch = globalThis.fetch
afterEach(() => {
	globalThis.fetch = realFetch
})

// A fresh env per test: the memory client is cached per env and keeps its fetch.
const newEnv = () =>
	({ SUPERMEMORY_API_KEY: "sm_test", PUBLIC_URL: "" }) as unknown as Env

function stubDocuments(outcomes: Record<string, "done" | "failed" | 404 | "net">) {
	globalThis.fetch = (async (input: RequestInfo | URL) => {
		const url = new URL(input instanceof Request ? input.url : input)
		const id = url.pathname.split("/").pop() as string
		const outcome = outcomes[id]
		if (outcome === "net") throw new TypeError("fetch failed")
		if (outcome === 404) {
			return Response.json({ error: "not found" }, { status: 404 })
		}
		return Response.json({ id, status: outcome })
	}) as unknown as typeof fetch
}

function fakeAgent() {
	const deleted: string[] = []
	const agent = {
		sql: (strings: TemplateStringsArray, ...values: unknown[]) => {
			if (strings.join("?").includes("DELETE")) deleted.push(String(values[0]))
			return []
		},
	} as unknown as CompanyBrainAgent
	return { agent, deleted }
}

const mapping = (documentId: string, createdAt?: number): BrainNodeMapping => ({
	documentId,
	containerTag: "t",
	nodePath: "n",
	createdAt,
})

describe("reconcileBrainMemoryNodeMappings", () => {
	it("keeps done and unknown-error mappings, deletes failed and 404 ones", async () => {
		stubDocuments({ A: "done", B: "failed", C: 404, D: "net" })
		const { agent, deleted } = fakeAgent()
		const kept = await reconcileBrainMemoryNodeMappings(
			newEnv(),
			"org",
			agent,
			["A", "B", "C", "D"].map((id) => mapping(id)),
		)
		expect(kept.map((m) => m.documentId)).toEqual(["A", "D"])
		expect(deleted.sort()).toEqual(["B", "C"])
	}, 30_000)

	it("keeps a freshly written mapping that 404s", async () => {
		stubDocuments({ A: 404, B: 404 })
		const { agent, deleted } = fakeAgent()
		const now = 1_000_000_000
		const kept = await reconcileBrainMemoryNodeMappings(
			newEnv(),
			"org",
			agent,
			[mapping("A", now - 1000), mapping("B", now - NOT_FOUND_GRACE_MS)],
			now,
		)
		expect(kept.map((m) => m.documentId)).toEqual(["A"])
		expect(deleted).toEqual(["B"])
	})
})
