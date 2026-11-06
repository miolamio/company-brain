import { describe, expect, it } from "vitest"
import { privateContainerTagFor } from "@/lib/spaces/provisioning"
import { resolveBrainReadContainerTags } from "../memory/read-scope"
import { slackMemoryContainerTag } from "../memory/writeback"
import { ensureChannelMembershipTables } from "../slack/channel-membership"
import type { CompanyBrainAgent } from "../turn/agent"
import { scheduledRunMemoryScope } from "./schedule-derive"

// A real SQLite stands in for the Durable Object's `sql` tag. The specifier is
// built at runtime because tsc has no declarations for bun:sqlite.
const { Database } = (await import(["bun", "sqlite"].join(":"))) as {
	Database: new (path: string) => {
		prepare: (sql: string) => { all: (...v: unknown[]) => unknown[] }
	}
}

// The owner's two identities: the org member id keys their employee memory,
// the Slack id resolves which private channels they belong to.
const owner = { creatorUserId: "member_42", creatorSlackUserId: "U042" }

function agentWhereOwnerIsIn(channelId: string) {
	const db = new Database(":memory:")
	const sql = (strings: TemplateStringsArray, ...values: unknown[]) =>
		db.prepare(strings.join("?")).all(...values)
	const agent = { name: "org", sql } as unknown as CompanyBrainAgent
	ensureChannelMembershipTables(agent)
	sql`INSERT INTO brain_channel_membership (channel_id, slack_user_id, is_private, updated_at)
		VALUES (${channelId}, ${owner.creatorSlackUserId}, 1, 1)`
	return agent
}

describe("scheduled DM digest memory scope", () => {
	it("writes to the owner's employee memory, the container their DMs use", () => {
		const scope = scheduledRunMemoryScope(owner, true, "D042")
		expect(slackMemoryContainerTag(scope)).toBe(
			privateContainerTagFor("member_42"),
		)
	})

	it("reads the owner's employee memory and their private channels", () => {
		const tags = resolveBrainReadContainerTags(
			agentWhereOwnerIsIn("C0PRIV"),
			scheduledRunMemoryScope(owner, true, "D042"),
		)
		expect(tags).toContain(privateContainerTagFor("member_42"))
		expect(tags).toContain("slack_channel_C0PRIV")
		expect(tags).not.toContain(privateContainerTagFor("U042"))
	})

	it("keeps channel digests on the scope they were created with", () => {
		const memoryScope = { kind: "shared" as const, channelId: "C0PUB" }
		expect(
			scheduledRunMemoryScope({ ...owner, memoryScope }, false, "C0PUB"),
		).toBe(memoryScope)
	})
})
