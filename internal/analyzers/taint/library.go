package taint

import (
	"regexp"
	"strings"
)

// A method matched as SQL by its name alone - execute, query - on an object the code builds from
// another library's class is that library's method: client = DefaultClient() from a payments SDK
// sends a signed API request in client.execute(request). libraryOf reads which library the code
// builds the receiver from, by the file's own imports; dbLibrary names the libraries that run
// queries, read broadly, so that any doubt keeps the finding as it was.

// dbLibrary matches a module path of a database driver, an ORM or query builder, a query engine
// or a data store of any kind
var dbLibrary = regexp.MustCompile(`(?i)sql|sqlite|postgres|psycopg|\bpg\b|pg8000|pgx|asyncpg|mysql|maria|mssql|tedious|oracle|db2|ibm_db|duck|clickhouse|snowflake|bigquery|redshift|athena|trino|presto|hive|impala|vertica|teradata|databricks|spark|neo4j|cypher|gremlin|graph|falkor|memgraph|arango|cassandra|scylla|cockroach|supabase|prisma|knex|sequelize|typeorm|drizzle|kysely|slonik|libsql|turso|neon|planetscale|alchemy|peewee|pony|tortoise|django|odbc|jdbc|database|data_?base|\bdb\b|[._/-]db|db[._/-]|^db|db$|dbapi|records|dataset|pandas|polars|ibis|dask|arrow|lance|milvus|weaviate|qdrant|chroma|pinecone|elastic|opensearch|solr|mongo|redis|influx|timescale|quest|kusto|cosmos|dynamo|firestore|firebase|couch|realm|rethink|orient|surreal|edgedb|fauna|hasura|graphql|sheets|gspread|airtable|excel|csv|parquet|query|sequel|store|storage|cache|index|search|warehouse|lake|olap|cube|metabase|superset|looker|tableau|grafana|prometheus|loki|splunk|sumo|datadog|kql|logs?\b|analytics|gorm|\bent\b|bun|sqlx|xorm|beego|mgo|bolt|badger|level|rocks|lmdb|tinydb|zodb|shelve|dbm|pickle|h5|hdf|zarr|xarray|vector|embedding|faiss|annoy|hnsw|usearch|marqo|vespa|typesense|meili|algolia|tantivy|whoosh|lucene|spanner|table|rds\b|aurora|firebird|sybase|hana|exasol|dremio|druid|pinot|kylin|doris|starrocks|tidb|yugabyte|greenplum|singlestore|memsql|materialize|risingwave|crate|monet|\bh2\b|derby|hsql|ledger|kv\b|etcd|consul`)

// vendorLibrary matches a module path that says it is a client of another service's API - an
// SDK, an API or HTTP client, a cloud or SaaS vendor's package. A module whose name says nothing
// (backends, core, engine) may be anything, a database included, and keeps the finding.
var vendorLibrary = regexp.MustCompile(`(?i)sdk|api|client|rest\b|grpc|http|boto|aws|azure|gcp|google|openai|anthropic|stripe|paypal|braintree|adyen|square|twilio|sendgrid|mailgun|postmark|slack|discord|telegram|github|gitlab|jira|atlassian|notion|linear|asana|trello|hubspot|salesforce|shopify|zendesk|intercom|mixpanel|sentry|pagerduty|kubernetes|k8s|docker|langchain|llama|transformers|huggingface|cohere|mistral|gemini|vertex|bedrock|replicate|kendra|payments?|billing|kafka|rabbit|pika|celery|temporal`)

var (
	// an origin's leading name: DefaultClient(), payments.Client(...), new Client(), type Session
	originHead    = regexp.MustCompile(`^(?:type\s+\*?|await\s+|new\s+)*([A-Za-z_$][\w$]*)(?:\s*\.\s*([A-Za-z_$][\w$]*))*`)
	pyFromImport  = regexp.MustCompile(`(?m)^\s*from\s+([\w.]+)\s+import\s+(\([^)]*\)|[^\n#]+)`)
	pyImport      = regexp.MustCompile(`(?m)^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*$`)
	jsImportFrom  = regexp.MustCompile(`(?m)^\s*import\s+(?:type\s+)?([^;]*?)\s+from\s+["']([^"']+)["']`)
	jsRequire     = regexp.MustCompile(`(?m)(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*=\s*require\(\s*["']([^"']+)["']\s*\)`)
	goImportLine  = regexp.MustCompile(`(?m)^\s*(?:import\s+)?(\w+\s+)?"([^"]+)"\s*$`)
	importedNames = regexp.MustCompile(`[A-Za-z_$][\w$]*(?:\s+as\s+[A-Za-z_$][\w$]*)?`)
)

// libraryOf is the module the receiver's origin comes from - a constructor, a factory or a type
// the file imports from a module outside the project - and the module with the imported name:
// payments_sdk and payments_sdk.DefaultClient, google.cloud and google.cloud.bigquery. "" when
// the origin names nothing the file imports, or the import is the project's own.
func (c *ctx) libraryOf(src []byte, origin string) (mod, full string) {
	o := strings.TrimSpace(origin)
	m := originHead.FindStringSubmatch(o)
	if m == nil {
		return "", ""
	}
	rest := strings.TrimSpace(o[len(m[0]):])
	if !strings.HasPrefix(o, "type ") && !strings.HasPrefix(rest, "(") && !strings.HasPrefix(rest, "<") {
		return "", "" // not a call or a declared type: a variable, a literal, an expression
	}
	mod, full = importedModule(string(src), m[1])
	if mod == "" || strings.HasPrefix(mod, ".") || strings.HasPrefix(mod, "/") || strings.HasPrefix(mod, "@/") || strings.HasPrefix(mod, "~/") {
		return "", ""
	}
	if c.projectModule(full) {
		return "", ""
	}
	return mod, full
}

// importedModule is the module a file imports name from, and the module with the name: "" when
// it does not
func importedModule(text, name string) (mod, full string) {
	for _, m := range pyFromImport.FindAllStringSubmatch(text, -1) {
		for _, n := range importedNames.FindAllString(strings.Trim(m[2], "()"), -1) {
			f := strings.Fields(n)
			if f[len(f)-1] == name {
				return m[1], m[1] + "." + f[0]
			}
		}
	}
	for _, m := range pyImport.FindAllStringSubmatch(text, -1) {
		if m[2] == name || m[2] == "" && strings.SplitN(m[1], ".", 2)[0] == name {
			return m[1], m[1]
		}
	}
	for _, m := range jsImportFrom.FindAllStringSubmatch(text, -1) {
		if jsBinds(m[1], name) {
			return m[2], m[2]
		}
	}
	for _, m := range jsRequire.FindAllStringSubmatch(text, -1) {
		if jsBinds(m[1], name) {
			return m[2], m[2]
		}
	}
	for _, m := range goImportLine.FindAllStringSubmatch(text, -1) {
		alias := strings.TrimSpace(m[1])
		if alias == name || alias == "" && m[2][strings.LastIndexByte(m[2], '/')+1:] == name {
			return m[2], m[2]
		}
	}
	return "", ""
}

// jsBinds reports whether an import clause binds name: X, * as X, { A, B as X }, X, { Y }
func jsBinds(clause, name string) bool {
	clause = strings.ReplaceAll(strings.ReplaceAll(clause, "{", " "), "}", " ")
	for _, part := range strings.Split(clause, ",") {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		if f[len(f)-1] == name {
			return true
		}
	}
	return false
}

// projectModule reports whether a module path names the project's own code: a file or a folder
// of the tree with that name
func (c *ctx) projectModule(mod string) bool {
	segs := moduleSegments(strings.TrimPrefix(mod, "@"))
	if len(segs) == 0 {
		return true
	}
	last := segs[len(segs)-1]
	for f := range c.g.Files {
		fs := moduleSegments(f)
		if segmentsHaveSuffix(fs, segs) {
			return true
		}
		for _, s := range fs {
			if s == segs[0] || s == last {
				return true // a folder of the tree: a package of this project or a workspace
			}
		}
	}
	return false
}
