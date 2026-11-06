import { describe, expect, it } from "vitest"
import type { CompanyBrainAgent } from "../turn/agent"
import {
	applyMembershipEvent,
	ensureChannelMembershipTables,
	readableSlackChannelContainerTagsForUser,
} from "./channel-membership"

// A real SQLite stands in for the Durable Object's `sql` tag. The specifier is
// built at runtime because tsc has no declarations for bun:sqlite.
const { Database } = (await import(["bun", "sqlite"].join(":"))) as {
	Database: new (path: string) => {
		prepare: (sql: string) => { all: (...v: unknown[]) => unknown[] }
	}
}

function fakeAgent() {
	const db = new Database(":memory:")
	const sql = (strings: TemplateStringsArray, ...values: unknown[]) =>
		db.prepare(strings.join("?")).all(...values)
	return { name: "org", sql } as unknown as CompanyBrainAgent
}

function seed(agent: CompanyBrainAgent) {
	ensureChannelMembershipTables(agent)
	agent.sql`
		INSERT INTO brain_channel_membership (channel_id, slack_user_id, is_private, updated_at)
		VALUES (${"C1"}, ${"U1"}, 1, ${0})
	`
}

const failingPrivacy = async (): Promise<boolean | null> => {
	throw new Error("slack down")
}

describe("applyMembershipEvent", () => {
	it("revokes DM access on leave even when the privacy lookup fails", async () => {
		const agent = fakeAgent()
		seed(agent)
		expect(readableSlackChannelContainerTagsForUser(agent, "U1")).toHaveLength(1)

		await applyMembershipEvent(
			agent,
			{ channel: "C1", user: "U1", isLeave: true, isBot: false },
			{ resolvePrivacy: failingPrivacy, backfill: async () => 0 },
		)

		expect(readableSlackChannelContainerTagsForUser(agent, "U1")).toEqual([])
	})

	it("purges the channel when the bot itself leaves", async () => {
		const agent = fakeAgent()
		seed(agent)
		await applyMembershipEvent(
			agent,
			{ channel: "C1", user: "UBOT", isLeave: true, isBot: true },
			{ resolvePrivacy: failingPrivacy, backfill: async () => 0 },
		)
		expect(readableSlackChannelContainerTagsForUser(agent, "U1")).toEqual([])
	})

	it("purges the channel on any leave when the bot id is unknown", async () => {
		const agent = fakeAgent()
		seed(agent)
		agent.sql`
			INSERT INTO brain_channel_membership (channel_id, slack_user_id, is_private, updated_at)
			VALUES (${"C1"}, ${"U9"}, 1, ${0})
		`
		await applyMembershipEvent(
			agent,
			{ channel: "C1", user: "UBOT", isLeave: true, isBot: false, botUnknown: true },
			{ resolvePrivacy: failingPrivacy, backfill: async () => 0 },
		)
		expect(readableSlackChannelContainerTagsForUser(agent, "U1")).toEqual([])
		expect(readableSlackChannelContainerTagsForUser(agent, "U9")).toEqual([])
	})

	it("keeps other members when a known non-bot leaves", async () => {
		const agent = fakeAgent()
		seed(agent)
		agent.sql`
			INSERT INTO brain_channel_membership (channel_id, slack_user_id, is_private, updated_at)
			VALUES (${"C1"}, ${"U9"}, 1, ${0})
		`
		await applyMembershipEvent(
			agent,
			{ channel: "C1", user: "U1", isLeave: true, isBot: false, botUnknown: false },
			{ resolvePrivacy: failingPrivacy, backfill: async () => 0 },
		)
		expect(readableSlackChannelContainerTagsForUser(agent, "U9")).toHaveLength(1)
	})

	it("records a join only for a private channel", async () => {
		const agent = fakeAgent()
		ensureChannelMembershipTables(agent)
		const join = (isPrivate: boolean | null) =>
			applyMembershipEvent(
				agent,
				{ channel: "C2", user: "U2", isLeave: false, isBot: false },
				{ resolvePrivacy: async () => isPrivate, backfill: async () => 0 },
			)
		await join(false)
		await join(null)
		expect(readableSlackChannelContainerTagsForUser(agent, "U2")).toEqual([])
		await join(true)
		expect(readableSlackChannelContainerTagsForUser(agent, "U2")).toHaveLength(1)
	})
})
