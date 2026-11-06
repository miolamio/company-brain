import { describe, expect, it } from "vitest"
import {
	classifySqlInput,
	isQueryTool,
	queryToolCallHasDdl,
	queryToolCallHasDml,
	sqlContainsDdl,
	sqlContainsDml,
} from "./sql-query-check"

const flagged = (sql: string) => sqlContainsDml(sql) || sqlContainsDdl(sql)

describe("SQL check bypass attempts", () => {
	it.each([
		["lowercase", "delete from t"],
		["mixed case", "DeLeTe FrOm t"],
		["leading block comment", "/* x */ DELETE FROM t"],
		["leading line comment", "-- x\nDELETE FROM t"],
		["CTE then DELETE", "WITH x AS (SELECT 1) DELETE FROM t"],
		["CTE then UPDATE", "WITH x AS (SELECT 1) UPDATE t SET a = 1"],
		["second statement", "SELECT 1; DROP TABLE t"],
		["second statement, no space", "SELECT 1;DELETE FROM t"],
		["tabs and newlines", "\t\n DELETE\r\n\tFROM t"],
		["comment between keywords", "DELETE/**/FROM t"],
		["line comment between keywords", "DELETE--x\nFROM t"],
		["-- inside a string, then a statement", "SELECT 'a--b'; DELETE FROM t"],
		["/* inside a string, then a statement", "SELECT '/*'; DELETE FROM t; SELECT '*/'"],
		["doubled quote in a string", "SELECT 'it''s'; DELETE FROM t"],
		["backslash-escaped quote (MySQL reading)", "SELECT 'a\\'; DELETE FROM t; --'"],
		["dollar-quoted string, then a statement", "SELECT $q$x$q$; DELETE FROM t"],
		["quoted table name", 'UPDATE "my table" SET a = 1'],
		["backticked table name", "UPDATE `my table` SET a = 1"],
		["UPDATE with alias", "UPDATE t AS x SET a = 1"],
		["MySQL UPDATE IGNORE", "UPDATE IGNORE t SET a = 1"],
		["INSERT without INTO", "INSERT t VALUES (1)"],
		["EXPLAIN ANALYZE of a write", "EXPLAIN ANALYZE DELETE FROM t"],
		["SELECT INTO a new table", "SELECT * INTO newt FROM t"],
		["CREATE TABLE AS", "CREATE TABLE x AS SELECT 1"],
		["COPY", "COPY t FROM '/tmp/x'"],
		["GRANT", "GRANT ALL ON t TO u"],
		["DROP of an object the old list lacked", "DROP POLICY p ON t"],
		["CALL", "CALL purge()"],
		["DO block", "SELECT 1; DO $$ BEGIN DELETE FROM t; END $$"],
		["MySQL executable comment", "SELECT 1 /*! ; DELETE FROM t */"],
		["MySQL # comment hiding a statement", "SELECT 1 # '\nDELETE FROM t # '"],
		["DELETE with multi-table JOIN", "DELETE t1 FROM t1 JOIN t2 ON t1.id = t2.id"],
		["DELETE without FROM", "DELETE t"],
		["DELETE TOP", "DELETE TOP (5) FROM t"],
		["UPDATE of two tables", "UPDATE a, b SET a.x = b.y"],
		["UPDATE bracketed name", "UPDATE [dbo].[t] SET a = 1"],
		["UPDATE TOP", "UPDATE TOP (10) t SET a = 1"],
		["REPLACE without INTO", "REPLACE t VALUES (1)"],
		["MERGE without INTO", "MERGE t USING s ON t.id = s.id WHEN MATCHED THEN DELETE"],
		["EXPLAIN ANALYZE CREATE TABLE AS", "EXPLAIN ANALYZE CREATE TABLE x AS SELECT 1"],
		["T-SQL SELECT then EXEC", "SELECT 1 EXEC sp_x"],
		["BEGIN TRAN EXEC", "BEGIN TRAN EXEC sp_x"],
		["PRAGMA assignment", "PRAGMA writable_schema = 1"],
		["SET ROLE", "SET ROLE admin"],
		["SET SESSION AUTHORIZATION", "SET SESSION AUTHORIZATION postgres"],
		["SET search_path", "SET search_path = evil"],
		["dblink_exec in SELECT", "SELECT dblink_exec('host=x', 'DELETE FROM t')"],
		["pg_terminate_backend", "SELECT pg_terminate_backend(123)"],
		["lo_import", "SELECT lo_import('/etc/passwd')"],
		["pg_write_file", "SELECT pg_write_file('/tmp/x', 'y')"],
		["set_config", "SELECT set_config('role', 'admin', false)"],
		["schema-qualified set_config", "SELECT pg_catalog.set_config('a', 'b', false)"],
		["nextval", "SELECT nextval('s')"],
		["setval", "SELECT setval('s', 1)"],
		["pg_sleep", "SELECT pg_sleep(100)"],
		["dollar quote that is only an identifier in MySQL", "SELECT $q$; DELETE FROM t; $q$"],
		["dollar tag glued to an identifier", "SELECT a$q$; DELETE FROM t; SELECT $q$"],
		["bracket identifier hiding nothing", "SELECT [a]; DELETE FROM t"],
		["SELECT INTO OUTFILE", "SELECT 1 INTO OUTFILE '/tmp/x'"],
		["ON CONFLICT DO UPDATE", "INSERT INTO t VALUES (1) ON CONFLICT DO UPDATE SET a = 1"],
	])("flags %s", (_name, sql) => {
		expect(flagged(sql)).toBe(true)
	})

	it.each([
		["SELECT * FROM t WHERE a = 'x--y' AND b = 2"],
		["SELECT 'DELETE FROM t'"],
		["SELECT * FROM t FOR UPDATE"],
		["SELECT \"update\", \"drop\" FROM t"],
		["SELECT created_at FROM t ORDER BY created_at DESC"],
		["WITH x AS (SELECT 1) SELECT * FROM x"],
		["SELECT 1"],
		["SELECT * FROM t;"],
		["SHOW TABLES"],
		["DESCRIBE users"],
		["DESC users"],
		["EXPLAIN SELECT * FROM t"],
		["VALUES (1), (2)"],
		["TABLE users"],
		["SELECT updated_at, deleted_at FROM t"],
		["SELECT 'drop table x', 'delete from y' FROM t"],
		["SELECT replace(name, 'a', 'b') FROM t"],
		["SELECT t.drop, t.update FROM t"],
		["SELECT * FROM t -- DELETE FROM t"],
		["SELECT a # b FROM t"],
		["SELECT * FROM t FOR NO KEY UPDATE"],
	])("does not flag %s", (sql) => {
		expect(flagged(sql)).toBe(false)
	})
})

describe("whole-call classification", () => {
	const sqlTool = "run_query"

	it("looks inside JSON-encoded strings", () => {
		expect(queryToolCallHasDml(sqlTool, { payload: '{"sql":"DELETE FROM t"}' })).toBe(true)
		expect(queryToolCallHasDml(sqlTool, { payload: JSON.stringify({ a: [JSON.stringify({ q: "DELETE FROM t" })] }) })).toBe(true)
		expect(queryToolCallHasDdl(sqlTool, { payload: '[{"sql":"DROP TABLE t"}]' })).toBe(true)
		expect(queryToolCallHasDml(sqlTool, { payload: '{"sql":"SELECT 1"}' })).toBe(false)
	})

	it("does not flag prose or parameter values", () => {
		for (const text of [
			"look into the outage",
			"how to drop table in postgres",
			"what changed in billing?",
			"please insert into the doc",
			"start",
			"set",
			"2024-01-01",
		]) {
			expect(queryToolCallHasDml(sqlTool, { query: text })).toBe(false)
			expect(queryToolCallHasDdl(sqlTool, { query: text })).toBe(false)
		}
	})

	it("still catches statements whose grammar is split by comments", () => {
		for (const sql of ["UPDATE/**/t/**/SET a=1", "DELETE/**/FROM t", "DROP/**/TABLE t", "insert/**/into t values (1)"]) {
			expect(
				queryToolCallHasDml(sqlTool, { sql }) || queryToolCallHasDdl(sqlTool, { sql }),
			).toBe(true)
		}
	})

	it("fails closed on a huge argument instead of throwing", () => {
		const huge = Array.from({ length: 300_000 }, () => "a")
		expect(queryToolCallHasDml(sqlTool, { huge })).toBe(true)
		expect(queryToolCallHasDml(sqlTool, { sql: `SELECT ${"x,".repeat(60_000)}1` })).toBe(true)
	})

	it("fails closed on a getter that throws", () => {
		const bad = {
			get sql(): string {
				throw new Error("boom")
			},
		}
		expect(queryToolCallHasDml(sqlTool, bad)).toBe(true)
	})

	it("recognises the wider set of query tool names", () => {
		for (const name of ["execute_statement", "db_exec", "run_sql", "execute", "db_query"]) {
			expect(isQueryTool(name)).toBe(true)
		}
		for (const name of ["search_issues", "get_user", "list_tables", "create_issue"]) {
			expect(isQueryTool(name)).toBe(false)
		}
	})
})

const needsApproval = (sql: string) => classifySqlInput({ sql }) !== "read"

describe("redesign: SQL gate and strict judge", () => {
	it.each([
		// 1. strings the old shape gate treated as prose
		"use db; drop table users",
		"end; drop table users",
		"set @a=1; drop table users",
		"start slave; drop table t",
		"close c; delete from t",
		"delete t1, t2 from t1 join t2 on t1.a=t2.a",
		"DELETE t1.* FROM t1 JOIN t2 ON 1=1",
		"delete #t where a=1",
		"insert into t as x values (1)",
		"INSERT INTO t VALUE (1)",
		'INSERT INTO t FORMAT JSONEachRow {"a":1}',
		"INSERT INTO t BY NAME SELECT 1 AS a",
		"INSERT INTO FUNCTION s3('x') SELECT 1",
		"insert into #t select 1",
		"SET @@GLOBAL.read_only = 1",
		"call purge_all",
		"do sleep(100)",
		// 3. unicode identifiers
		"with café as (delete from t returning *) select * from café",
		"insert into tést values (1)",
		// 4. objects once missing from drop/alter/create lists
		"drop dictionary d",
		"drop owned by bob",
		"drop macro m",
		"drop synonym s",
		"alter default privileges grant all on tables to public",
		"alter dictionary d",
		"alter login sa with password='x'",
		"create transient table t as select 1",
		"create or alter view v as select 1",
		"create macro m() as 1",
		"create secret s (type s3)",
		// 5. start words
		"OPTIMIZE TABLE t FINAL DEDUPLICATE",
		"SYSTEM DROP DNS CACHE",
		"KILL QUERY WHERE 1",
		"PUT file:///x @stage",
		"REMOVE @stage",
		"EXPORT DATA OPTIONS(uri='gs://b/*') AS SELECT 1",
		"INSTALL httpfs",
		"BULK INSERT t FROM 'f'",
		"FLUSH TABLES",
		"BACKUP DATABASE d TO DISK='x'",
		"PURGE BINARY LOGS BEFORE now()",
		"UNDROP TABLE t",
		"DBCC FREEPROCCACHE",
		"SHUTDOWN",
		"STOP SLAVE",
		"truncate table t",
		"rename table a to b",
		// 2. quoted function names
		"select \"nextval\"('s')",
		"select pg_catalog.\"set_config\"('a','b',false)",
		"select \"pg_terminate_backend\"(1)",
		"select `load_file`('/etc/passwd')",
		"select [pg_sleep](10)",
		// 6. side-effect functions
		"SELECT pg_reload_conf()",
		"SELECT pg_notify('c','x')",
		"select pg_stat_reset()",
		"select pg_switch_wal()",
		"select system$cancel_all_queries(1)",
		"select load_extension('x')",
		"select writefile('/tmp/x','y')",
		"SELECT * FROM OPENQUERY(srv,'delete from t')",
		"SELECT query_to_xml('select pg_terminate_backend(1)', true, false, '')",
		"SELECT query_to_xml('delete from t', true, false, '')",
		"SELECT * FROM dblink('x','delete from t')",
		"SELECT lo_unlink(1)",
		"select sleep(1000)",
		"SELECT * FROM url('http://x', CSV)",
		"SELECT * FROM s3('x')",
		"SELECT * FROM remote('h', db.t)",
		"SELECT * FROM read_csv('/etc/passwd')",
		// 7. T-SQL batches without a semicolon
		"select 1 from t where 1=1 kill 55",
		"select 1 from t where 1=1 delete from t",
		"select 1 from t where 1=1 exec('x')",
		// misc from the probe script
		"﻿delete from t",
		"\u200bdelete from t",
		"delete\u200bfrom t",
		"/*x*/ (delete from t)",
		";delete from t",
		"# c\ndelete from t",
		"--c\ndelete from t",
		"select 1 /*!50000 ; drop table t */",
		"COPY (SELECT 1) TO PROGRAM 'x'",
		"COPY INTO @s FROM t",
		"ATTACH 'x.db' AS x",
		"VACUUM INTO 'x'",
		"explain analyze delete from t",
		"select * into t2 from t",
		"select 1 into outfile '/tmp/x'",
		// Known false positive kept as an approval: a dollar-quote reading
		// must not hide a `;` from the MySQL reading, so this cannot be told
		// from `SELECT $$; DELETE FROM t; $$`.
		"SELECT $$a;b$$",
		"SELECT $$; DELETE FROM t; $$",
		// Prose that starts with a SQL verb is judged as SQL and needs approval.
		"update the config to set X",
	])("needs approval: %s", (sql) => {
		expect(needsApproval(sql)).toBe(true)
	})

	it("fully SQL-looking nested JSON still needs approval", () => {
		const nested = JSON.stringify({ a: JSON.stringify({ q: "delete from t" }) })
		expect(classifySqlInput({ x: nested })).not.toBe("read")
	})

	it.each([
		"SELECT event, count() FROM events WHERE timestamp > now() - INTERVAL 7 DAY GROUP BY event ORDER BY count() DESC LIMIT 10",
		"SELECT properties.$browser, uniq(distinct_id) FROM events GROUP BY 1",
		"WITH c AS (SELECT user_id, updated_at, deleted_at FROM users WHERE deleted_at IS NULL) SELECT user_id, row_number() OVER (PARTITION BY user_id ORDER BY updated_at DESC) AS rn, sum(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) OVER (PARTITION BY user_id) FROM c",
		'SELECT "drop", "set", "delete" FROM t ORDER BY "drop"',
		"SELECT * FROM t WHERE status = 'deleted' AND note LIKE '%drop table%'",
		"SELECT pg_size_pretty(pg_total_relation_size('t'))",
		"SELECT pg_size_pretty(pg_database_size(current_database()))",
		"SHOW TABLES",
		"DESCRIBE t",
		"EXPLAIN SELECT 1",
		"select user, `desc`, `call`, `end` from t",
		"SELECT * FROM system.tables",
		"SELECT * FROM t ORDER BY a FETCH FIRST 10 ROWS ONLY",
		"SELECT * FROM t WHERE x = 1 LOCK IN SHARE MODE",
		"SELECT * FROM t FOR UPDATE",
		"SELECT * FROM t FOR NO KEY UPDATE",
		"SELECT sum(replace(a,'x','y')), truncate(b, 2), insert('abc', 1, 1, 'x') FROM t",
		"select * from orders o where o.set_id = 1 and o.truncated = false",
		"select current_date, now(), exec_time, executed_at from jobs",
		"select * from information_schema.tables where table_name like 'load%'",
		"SELECT * FROM t -- delete later\nWHERE a=1",
		"select * from t where x = ANY(ARRAY[1,2]) ; ",
	])("stays read: %s", (sql) => {
		expect(needsApproval(sql)).toBe(false)
	})

	it("ignores prose that does not start with a SQL keyword", () => {
		for (const text of ["look into the outage", "how to drop a table", "what changed in billing?"]) {
			expect(classifySqlInput({ query: text })).toBe("read")
		}
	})

	it("treats prose that starts with a SQL verb as SQL (documented trade-off)", () => {
		// "update ..." is judged as SQL and needs approval; "show me errors" is a
		// read keyword with no statement word after it, so it passes.
		expect(needsApproval("update the config")).toBe(true)
		expect(needsApproval("show me errors")).toBe(false)
	})

	it("marks DDL as destructive anywhere in a statement", () => {
		expect(classifySqlInput({ sql: "select 1 from t drop table x" })).toBe("destructive")
	})
})
