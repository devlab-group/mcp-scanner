package taint

import (
	"testing"
)

// Node's digest("hex") holds only 0-9a-f, like Python's hexdigest(): a lock file named by it stays
// where the server put it. The raw value next to the digest is still a path.
func TestNodeHexDigestCarriesNoPath(t *testing.T) {
	const src = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createHmac } from "crypto";
import { unlinkSync } from "fs";

const server = new McpServer({ name: "x", version: "1.0.0" });
server.tool("release_lock", "Release a session lock.", { session: z.string() }, async ({ session }) => {
  const id = createHmac("sha1", "k").update(session).digest("hex").slice(0, 16);
  unlinkSync("/run/locks/" + id + ".lock");
  return { content: [{ type: "text", text: "ok" }] };
});
server.tool("release_named", "Release a session lock.", { session: z.string() }, async ({ session }) => {
  const id = createHmac("sha1", "k").update(session).digest("hex") + "-" + session;
  unlinkSync("/run/locks/" + id + ".lock");
  return { content: [{ type: "text", text: "ok" }] };
});
`
	res := analyze(t, mustWriteDir(t, map[string]string{"server.ts": src}))
	got := categoryFindings(res, "path_traversal")
	if len(got) != 1 || got[0].Line != 14 {
		t.Fatalf("want one finding, in release_named (line 14), got %+v", got)
	}
}

func TestMaskHexEncodings(t *testing.T) {
	cases := map[string]bool{ // text -> whether "p" stays visible
		`createHmac("sha1", key).update(p).digest("hex")`:        false,
		`createHash('md5').update(p).digest('hex').slice(0, 8)`:  false,
		`hashlib.sha256(p.encode("utf-8")).hexdigest()`:          false,
		`hex.EncodeToString(sha.Sum(p))`:                         false,
		`fmt.Sprintf("%s/%s", hex.EncodeToString(h(p)), p)`:      true,
		`createHash("md5").update(p).digest("base64")`:           true,
		`"/tmp/" + hashlib.sha1(p).hexdigest()[:8] + "/" + p`:    true,
		"`${createHash('sha256').update(p).digest('hex')}-${p}`": true,
	}
	for text, visible := range cases {
		masked, _ := maskHexEncodings(text)
		if got := mentionsIdent(masked, "p"); got != visible {
			t.Errorf("%q -> %q: p visible %v, want %v", text, masked, got, visible)
		}
	}
}
