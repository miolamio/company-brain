import { describe, expect, it } from "vitest"

import { parseTriageResult } from "./triage"

describe("parseTriageResult", () => {
	it("accepts ANSWER output without an optional audit reason", () => {
		expect(
			parseTriageResult(`ANSWER
Priority: normal`),
		).toEqual({
			decision: "answer",
			source: "model",
			priority: "normal",
		})
	})

	it.each([
		"Reason",
		"reason",
		"ReAsOn",
	])("accepts ANSWER output with a %s audit reason", (reasonField) => {
		expect(
			parseTriageResult(`ANSWER
Priority: normal
${reasonField}: The user asked a direct question.`),
		).toEqual({
			decision: "answer",
			source: "model",
			priority: "normal",
		})
	})

	it("accepts ANSWER output with both fallback and an audit reason", () => {
		expect(
			parseTriageResult(`ANSWER
Priority: low
Fallback: ack tada
Reason: A reaction would be sufficient if no fuller reply is needed.`),
		).toEqual({
			decision: "answer",
			source: "model",
			priority: "low",
			fallbackEmoji: "tada",
		})
	})

	it("parses the main-agent effort", () => {
		expect(
			parseTriageResult(`ANSWER
Priority: normal
AgentMainEffort: high`),
		).toEqual({
			decision: "answer",
			source: "model",
			priority: "normal",
			agentMainEffort: "high",
		})
	})

	it.each([
		`ANSWER
Priority: normal
Reason:`,
		`ANSWER
Priority: normal
Reason: First rationale.
rEaSoN: Second rationale.`,
		`ANSWER
Priority: normal
Unexpected: value`,
	])("keeps malformed ANSWER output on the safe fallback path", (output) => {
		expect(parseTriageResult(output, "channel")).toMatchObject({
			decision: "pass",
			source: "parse_fallback",
		})
	})
})
