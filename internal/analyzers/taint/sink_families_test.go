package taint

import (
	"fmt"
	"testing"

	"github.com/revinand/mcp-scanner/internal/testutil"
)

// Exercise otherwise uncovered sink catalog entries in each language's source syntax
func TestTaint_SinkFamiliesFire(t *testing.T) {
	const py = "import marshal\nimport os\nimport pickle\nimport sqlite3\nimport subprocess\n\nfrom flask import render_template_string\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP(\"ops\")\n\n\n" +
		"@mcp.tool()\ndef run(name: str) -> str:\n    \"\"\"Runs a job.\"\"\"\n    cur = sqlite3.connect(\"db\").cursor()\n    %s\n    return \"\"\n"
	const js = "const vm = require(\"vm\");\n\nfunction runHandler(ctx, args) {\n  return %s;\n}\n\nmodule.exports.register = function (server) {\n  server.registerTool(\"run\", { description: \"Runs a job\" }, runHandler);\n};\n"
	const goSrc = "package main\n\nimport (\n\t\"database/sql\"\n\t\"text/template\"\n)\n\nvar db *sql.DB\n\nfunc runHandler(ctx Context, args RunArgs) (string, error) {\n\t%s\n\treturn \"\", nil\n}\n\nfunc register(s *mcp.Server) {\n\ts.AddTool(&mcp.Tool{Name: \"run\", Description: \"Runs a job\"}, runHandler)\n}\n"
	const java = "package fixture;\n\nimport java.io.*;\nimport java.sql.*;\n\npublic class Jobs {\n    @Tool(name = \"run\", description = \"Runs a job\")\n    public void run(String name, Connection conn) throws Exception {\n        %s\n    }\n}\n"
	const rust = "use std::process::Command;\n\n#[tool(name = \"run\", description = \"Runs a job\")]\nfn run(name: String) -> String {\n    %s;\n    String::new()\n}\n"

	cases := []struct{ name, file, src, category string }{
		{"Python executemany", "server.py", fmt.Sprintf(py, `cur.executemany("INSERT INTO t VALUES ('" + name + "')", [])`), "sql_injection"},
		{"Python executescript", "server.py", fmt.Sprintf(py, `cur.executescript("DELETE FROM t WHERE n = '" + name + "'")`), "sql_injection"},
		{"Python pickle.loads", "server.py", fmt.Sprintf(py, `pickle.loads(name.encode())`), "deserialization"},
		{"Python marshal.loads", "server.py", fmt.Sprintf(py, `marshal.loads(name.encode())`), "deserialization"},
		{"Python render_template_string", "server.py", fmt.Sprintf(py, `render_template_string("Hello " + name)`), "template_injection"},
		{"Python subprocess.call", "server.py", fmt.Sprintf(py, `subprocess.call("make " + name, shell=True)`), "command_injection"},
		{"JavaScript vm.runInNewContext", "handler.js", fmt.Sprintf(js, `vm.runInNewContext(args.expr)`), "eval"},
		{"JavaScript vm.runInThisContext", "handler.js", fmt.Sprintf(js, `vm.runInThisContext(args.expr)`), "eval"},
		{"JavaScript vm.compileFunction", "handler.js", fmt.Sprintf(js, `vm.compileFunction(args.expr)`), "eval"},
		{"Go Exec", "main.go", fmt.Sprintf(goSrc, `db.Exec("DELETE FROM t WHERE n = '" + args.Name + "'")`), "sql_injection"},
		{"Go QueryRow", "main.go", fmt.Sprintf(goSrc, `db.QueryRow("SELECT v FROM t WHERE n = '" + args.Name + "'")`), "sql_injection"},
		{"Go ExecContext", "main.go", fmt.Sprintf(goSrc, `db.ExecContext(ctx, "DELETE FROM t WHERE n = '" + args.Name + "'")`), "sql_injection"},
		{"Go QueryRowContext", "main.go", fmt.Sprintf(goSrc, `db.QueryRowContext(ctx, "SELECT v FROM t WHERE n = '" + args.Name + "'")`), "sql_injection"},
		{"Go template.New", "main.go", fmt.Sprintf(goSrc, `template.New(args.Name)`), "template_injection"},
		{"Java executeQuery", "Jobs.java", fmt.Sprintf(java, "Statement stmt = conn.createStatement();\n        stmt.executeQuery(\"SELECT * FROM t WHERE n = '\" + name + \"'\");"), "sql_injection"},
		{"Java ObjectInputStream", "Jobs.java", fmt.Sprintf(java, `new ObjectInputStream(new ByteArrayInputStream(name.getBytes())).readObject();`), "deserialization"},
		// Also matches the receiver-blind query entry, but still pins Rust SQL detection
		{"Rust sqlx::query", "tool.rs", fmt.Sprintf(rust, `sqlx::query(&format!("SELECT * FROM t WHERE n = '{}'", name))`), "sql_injection"},
		{"Rust reqwest::get", "tool.rs", fmt.Sprintf(rust, `reqwest::get(&name)`), "ssrf"},
		{"Rust Command::new", "tool.rs", fmt.Sprintf(rust, `Command::new(&name).output()`), "command_injection"},
		{"Rust Template::new", "tool.rs", fmt.Sprintf(rust, `Template::new(&name)`), "template_injection"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := run(t, testutil.WriteTree(t, map[string]string{tc.file: tc.src}))
			if got := categoryFindings(res, tc.category); len(got) == 0 {
				t.Fatalf("no %s finding, got %+v (gaps %v)", tc.category, res.Findings, res.Coverage.Gaps())
			}
		})
	}
}

// Values read from the environment, files, or HTTP responses are sources without tool arguments
func TestTaint_NonHandlerSourcesFire(t *testing.T) {
	cases := []struct{ name, file, src string }{
		{"Go os.Getenv", "main.go", "package main\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\nfunc job() {\n\tcmd := os.Getenv(\"JOB\")\n\texec.Command(\"sh\", \"-c\", cmd).Run()\n}\n"},
		{"Go os.ReadFile", "main.go", "package main\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\nfunc job() {\n\tb, _ := os.ReadFile(\"/etc/job\")\n\texec.Command(\"sh\", \"-c\", string(b)).Run()\n}\n"},
		{"Go http.Get", "main.go", "package main\n\nimport (\n\t\"io\"\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc job() {\n\tresp, _ := http.Get(\"https://jobs.example/next\")\n\tb, _ := io.ReadAll(resp.Body)\n\texec.Command(\"sh\", \"-c\", string(b)).Run()\n}\n"},
		{"Python os.environ", "job.py", "import os\n\n\ndef job():\n    cmd = os.environ.get(\"JOB\")\n    os.system(cmd)\n"},
		{"Python os.getenv", "job.py", "import os\n\n\ndef job():\n    cmd = os.getenv(\"JOB\")\n    os.system(cmd)\n"},
		{"Python requests.get", "job.py", "import os\nimport requests\n\n\ndef job():\n    cmd = requests.get(\"https://jobs.example/next\").text\n    os.system(cmd)\n"},
		{"JavaScript process.env", "job.js", "const { exec } = require(\"child_process\");\n\nfunction job() {\n  const cmd = process.env.JOB;\n  exec(cmd);\n}\n"},
		{"JavaScript readFileSync", "job.js", "const fs = require(\"fs\");\nconst { exec } = require(\"child_process\");\n\nfunction job() {\n  const cmd = fs.readFileSync(\"/etc/job\", \"utf8\");\n  exec(cmd);\n}\n"},
		{"Java System.getenv", "Job.java", "package fixture;\n\npublic class Job {\n    public void job() throws Exception {\n        String cmd = System.getenv(\"JOB\");\n        Runtime.getRuntime().exec(cmd);\n    }\n}\n"},
		// Keep the read separate because sources nested in constructor arguments are not recognized
		{"Java Files.readAllBytes", "Job.java", "package fixture;\n\nimport java.nio.file.*;\n\npublic class Job {\n    public void job() throws Exception {\n        byte[] b = Files.readAllBytes(Path.of(\"/etc/job\"));\n        Runtime.getRuntime().exec(new String(b));\n    }\n}\n"},
		{"Rust env::var", "job.rs", "use std::process::Command;\n\nfn job() {\n    let cmd = std::env::var(\"JOB\").unwrap();\n    Command::new(\"sh\").arg(\"-c\").arg(&cmd).output().unwrap();\n}\n"},
		{"Rust std::fs::read", "job.rs", "use std::process::Command;\n\nfn job() {\n    let cmd = String::from_utf8(std::fs::read(\"/etc/job\").unwrap()).unwrap();\n    Command::new(\"sh\").arg(\"-c\").arg(&cmd).output().unwrap();\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := run(t, testutil.WriteTree(t, map[string]string{tc.file: tc.src}))
			if got := categoryFindings(res, "command_injection"); len(got) == 0 {
				t.Fatalf("no command_injection finding, got %+v", res.Findings)
			}
		})
	}
}
