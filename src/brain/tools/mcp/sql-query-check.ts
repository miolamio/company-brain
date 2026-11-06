/**
 * Finds SQL data-changing statements (DML) in the arguments of a query tool.
 *
 * Why: tools named `query`, `run_query` or `execute_sql` take free-form SQL.
 * The word "query" is on the read-verb list, so `query({ sql: "DELETE ..." })`
 * used to run with no Approve/Deny card. The tool's name cannot tell a SELECT
 * from a DELETE; the SQL text can.
 *
 * Scope, for tools whose name contains "query" or "sql":
 *   - DML (step 1): INSERT, UPDATE, DELETE, MERGE, REPLACE, UPSERT
 *   - DDL (step 2): DROP, ALTER, TRUNCATE
 */

/** Name tokens that mark a tool as one that runs caller-supplied SQL. */
const QUERY_TOOL_TOKENS = new Set(["query", "queries", "sql"])

const DML_PATTERNS: RegExp[] = [
	/\binsert\s+\w/i, // INSERT INTO, INSERT OR REPLACE INTO, MySQL INSERT t VALUES
	/\bupdate\s+(?!set\b)[\w."\s]+?\s+set\b/i, // UPDATE [ONLY|IGNORE] t [AS alias] SET
	/\binto\s+[^\s@]/i, // SELECT ... INTO newtable / OUTFILE, which writes
	/\bdelete\s+from\b/i, // DELETE FROM
	/\bdelete\s+(?!from\b)[\w."`[\]]+\s+where\b/i, // T-SQL: DELETE t WHERE
	/\bmerge\s+into\b/i, // MERGE INTO
	/\breplace\s+into\b/i, // MySQL REPLACE INTO
	/\bupsert\s+into\b/i, // UPSERT INTO (CockroachDB and others)
]

const DDL_PATTERNS: RegExp[] = [
	/\bdrop\s+\w/i, // DROP TABLE, DROP POLICY, ...
	/\balter\s+\w/i, // ALTER TABLE, ALTER USER, ...
	// Commands that change state or run code and have no read form.
	/(?:^|;)\s*(?:create|grant|revoke|call|exec|execute|do|copy|vacuum|reindex|cluster|lock|load|attach|detach|comment\s+on)\b/i,
	// TRUNCATE [TABLE] [ONLY] name. The name must follow a space, so the
	// numeric function TRUNCATE(price, 2) in a SELECT is not matched.
	/\btruncate\s+(?:table\s+)?(?:only\s+)?[\w."`[\]]/i,
]

/** Splits "runQuery" / "execute_sql" / "EXECUTE-SQL" into lowercase words. */
export function nameTokens(name: string): string[] {
	return name
		.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
		.replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
		.toLowerCase()
		.split(/[^a-z0-9]+/)
		.filter(Boolean)
}

export function isQueryTool(toolName: string): boolean {
	return nameTokens(toolName).some((token) => QUERY_TOOL_TOKENS.has(token))
}

/**
 * Removes comments and quoted text so that neither `-- DELETE FROM x` nor
 * `WHERE note = 'delete from list'` is mistaken for a statement.
 *
 * One left-to-right pass, because the order matters: `'a--b'; DELETE ...` is a
 * string followed by a statement, not a string cut short by a comment. Quoted
 * identifiers become a plain word so `UPDATE "my table" SET` still reads as an
 * UPDATE. Whether a backslash escapes a quote depends on the database (MySQL
 * yes, Postgres no), so callers scan both ways and flag if either flags.
 */
function stripCommentsAndLiterals(sql: string, backslashEscapes: boolean): string {
	let out = ""
	let i = 0
	while (i < sql.length) {
		const ch = sql[i] as string
		const next = sql[i + 1]
		if (ch === "-" && next === "-") {
			const end = sql.indexOf("\n", i)
			i = end === -1 ? sql.length : end
			out += " "
		} else if (ch === "/" && next === "*") {
			// Postgres nests block comments; treating them as nested is the safe
			// reading only if the nesting is closed, so fall back to the first "*/".
			const end = sql.indexOf("*/", i + 2)
			i = end === -1 ? sql.length : end + 2
			out += " "
		} else if (ch === "'" || ch === '"' || ch === "`") {
			let j = i + 1
			while (j < sql.length) {
				if (backslashEscapes && sql[j] === "\\") j += 2
				else if (sql[j] === ch && sql[j + 1] === ch) j += 2
				else if (sql[j] === ch) break
				else j += 1
			}
			i = j + 1
			out += ch === "'" ? "''" : "x"
		} else if (ch === "$") {
			const tag = /^\$[A-Za-z_]*\$/.exec(sql.slice(i))
			const end = tag ? sql.indexOf(tag[0], i + tag[0].length) : -1
			if (tag && end !== -1) {
				i = end + tag[0].length
				out += "''"
			} else if (tag) {
				// Unterminated: the rest of the text is the body.
				i = sql.length
				out += "''"
			} else {
				out += ch
				i += 1
			}
		} else {
			out += ch
			i += 1
		}
	}
	return out
}

function scan(sql: string, patterns: RegExp[]): boolean {
	return [false, true].some((backslashEscapes) => {
		const code = stripCommentsAndLiterals(sql, backslashEscapes)
		return patterns.some((pattern) => pattern.test(code))
	})
}

export function sqlContainsDml(sql: string): boolean {
	return scan(sql, DML_PATTERNS)
}

/** Every string value in the arguments, including inside objects and arrays. */
function stringValues(input: unknown, limit = 2_000): string[] {
	const out: string[] = []
	const stack: unknown[] = [input]
	while (stack.length && out.length < limit) {
		const value = stack.pop()
		if (typeof value === "string") out.push(value)
		else if (Array.isArray(value)) stack.push(...value)
		else if (value && typeof value === "object") stack.push(...Object.values(value))
	}
	return out
}

/** DROP, ALTER or TRUNCATE: statements that remove or restructure data. */
export function sqlContainsDdl(sql: string): boolean {
	return scan(sql, DDL_PATTERNS)
}

/** True when a query tool is being asked to run a data-changing statement. */
export function queryToolCallHasDml(toolName: string, input: unknown): boolean {
	if (!isQueryTool(toolName)) return false
	return stringValues(input).some(sqlContainsDml)
}

/** True when a query tool is being asked to drop, alter or truncate. */
export function queryToolCallHasDdl(toolName: string, input: unknown): boolean {
	if (!isQueryTool(toolName)) return false
	return stringValues(input).some(sqlContainsDdl)
}