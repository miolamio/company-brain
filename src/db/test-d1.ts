import { MIGRATIONS } from "./migrations.generated"

// A minimal D1 stand-in over bun:sqlite, enough for drizzle's d1 driver. The
// specifier is built at runtime because tsc has no declarations for bun:sqlite.
type SqliteStatement = {
	all: (...values: unknown[]) => Record<string, unknown>[]
	values: (...values: unknown[]) => unknown[][]
	run: (...values: unknown[]) => unknown
}
type SqliteDatabase = {
	prepare: (sql: string) => SqliteStatement
	exec: (sql: string) => void
}

const { Database } = (await import(["bun", "sqlite"].join(":"))) as {
	Database: new (path: string) => SqliteDatabase
}

function statement(sqlite: SqliteDatabase, sql: string, params: unknown[]) {
	const run = async () => {
		sqlite.prepare(sql).run(...params)
		return { success: true, results: [], meta: {} }
	}
	return {
		bind: (...values: unknown[]) => statement(sqlite, sql, values),
		run,
		all: async () => ({
			success: true,
			results: sqlite.prepare(sql).all(...params),
			meta: {},
		}),
		raw: async () => sqlite.prepare(sql).values(...params),
		first: async () => sqlite.prepare(sql).all(...params)[0] ?? null,
	}
}

/** An in-memory D1 with every bundled migration applied. */
export function createTestD1(): D1Database {
	const sqlite = new Database(":memory:")
	for (const migration of MIGRATIONS) {
		for (const sql of migration.statements) sqlite.exec(sql)
	}
	return {
		prepare: (sql: string) => statement(sqlite, sql, []),
		batch: async (statements: { run: () => Promise<unknown> }[]) =>
			Promise.all(statements.map((s) => s.run())),
	} as unknown as D1Database
}
