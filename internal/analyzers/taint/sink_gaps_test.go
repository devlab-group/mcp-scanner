package taint

import "testing"

func TestTaint_SubprocessGetoutput(t *testing.T) {
	base := "../../../testdata/source/taint/python/command_injection/getoutput"
	t.Run("vulnerable", func(t *testing.T) {
		res := analyze(t, base+"/vulnerable")
		if got := categoryFindings(res, "command_injection"); len(got) == 0 {
			t.Fatalf("want a command_injection finding, got none among %+v", res.Findings)
		}
	})
	t.Run("fixed", func(t *testing.T) {
		res := analyze(t, base+"/fixed")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding once shlex.quote is applied, got %+v", got)
		}
	})
	t.Run("benign", func(t *testing.T) {
		res := analyze(t, base+"/benign")
		if got := categoryFindings(res, "command_injection"); len(got) != 0 {
			t.Fatalf("want no command_injection finding when no tainted value reaches the shell call, got %+v", got)
		}
	})
}

func TestTaint_SubprocessGetstatusoutput(t *testing.T) {
	src := `import subprocess


def disk_usage_handler(directory: str) -> str:
    status, output = subprocess.getstatusoutput(f"du -sh {directory}")
    return output


def register(mcp):
    mcp.add_tool(disk_usage_handler, name="disk_usage", description="Reports disk usage for a directory")
`
	res := analyze(t, mustWriteDir(t, map[string]string{"handler.py": src}))
	if got := categoryFindings(res, "command_injection"); len(got) == 0 {
		t.Fatalf("want a command_injection finding via subprocess.getstatusoutput, got none among %+v", res.Findings)
	}
}

func TestTaint_OSOpenFile(t *testing.T) {
	base := "../../../testdata/source/taint/go/path_traversal/openfile"
	t.Run("vulnerable", func(t *testing.T) {
		res := analyze(t, base+"/vulnerable")
		if got := categoryFindings(res, "path_traversal"); len(got) == 0 {
			t.Fatalf("want a path_traversal finding, got none among %+v", res.Findings)
		}
	})
	t.Run("fixed", func(t *testing.T) {
		res := analyze(t, base+"/fixed")
		if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
			t.Fatalf("want no path_traversal finding once filepath.Base is applied, got %+v", got)
		}
	})
	t.Run("benign", func(t *testing.T) {
		res := analyze(t, base+"/benign")
		if got := categoryFindings(res, "path_traversal"); len(got) != 0 {
			t.Fatalf("want no path_traversal finding when no tainted value reaches the path, got %+v", got)
		}
	})
}

func TestTaint_ReceiverBlindSSRF(t *testing.T) {
	cases := []struct {
		name string
		base string
	}{
		{"go_http_client", "../../../testdata/source/taint/go/ssrf/method_receiver"},
		{"python_httpx_asyncclient", "../../../testdata/source/taint/python/ssrf/method_receiver"},
		{"javascript_axios", "../../../testdata/source/taint/javascript/ssrf/axios_get"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Run("vulnerable", func(t *testing.T) {
				res := analyze(t, c.base+"/vulnerable")
				if got := categoryFindings(res, "ssrf"); len(got) == 0 {
					t.Fatalf("want an ssrf finding, got none among %+v", res.Findings)
				}
			})
			t.Run("fixed", func(t *testing.T) {
				res := analyze(t, c.base+"/fixed")
				if got := categoryFindings(res, "ssrf"); len(got) != 0 {
					t.Fatalf("want no ssrf finding once the URL is one of a fixed set of literals, got %+v", got)
				}
			})
			t.Run("benign", func(t *testing.T) {
				res := analyze(t, c.base+"/benign")
				if got := categoryFindings(res, "ssrf"); len(got) != 0 {
					t.Fatalf("want no ssrf finding when no tainted value reaches the client call, got %+v", got)
				}
			})
		})
	}
}

func TestTaint_GatedGetPostDoNotFlagOrdinaryAccessors(t *testing.T) {
	cases := []struct {
		name string
		dir  string
	}{
		{"python_dict_get", "../../../testdata/source/taint/python/ssrf/method_receiver/benign"},
		{"typescript_map_get", "../../../testdata/source/taint/typescript/ssrf/cache_accessor/benign"},
		{"go_own_get_method", "../../../testdata/source/taint/go/ssrf/method_receiver/benign"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := analyze(t, c.dir)
			if got := categoryFindings(res, "ssrf"); len(got) != 0 {
				t.Fatalf("want no ssrf finding for an ordinary accessor, got %+v", got)
			}
		})
	}
}

func TestTaint_SinkFamilySiblings(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		category string
	}{
		{"python_shutil_copy2", "../../../testdata/source/taint/python/path_traversal/shutil_copy2", "path_traversal"},
		{"python_shutil_copyfile", "../../../testdata/source/taint/python/path_traversal/shutil_copyfile", "path_traversal"},
		{"python_shutil_copytree", "../../../testdata/source/taint/python/path_traversal/shutil_copytree", "path_traversal"},
		{"python_shutil_copyfileobj", "../../../testdata/source/taint/python/path_traversal/shutil_copyfileobj", "path_traversal"},
		{"python_os_removedirs", "../../../testdata/source/taint/python/path_traversal/os_removedirs", "path_traversal"},
		{"python_os_renames", "../../../testdata/source/taint/python/path_traversal/os_renames", "path_traversal"},
		{"python_yaml_load_all", "../../../testdata/source/taint/python/deserialization/yaml_load_all", "deserialization"},
		{"go_os_createtemp", "../../../testdata/source/taint/go/path_traversal/createtemp", "path_traversal"},
		{"go_http_newrequestwithcontext", "../../../testdata/source/taint/go/ssrf/newrequestwithcontext", "ssrf"},
		{"go_net_dialtimeout", "../../../testdata/source/taint/go/raw_socket/dialtimeout", "raw_socket"},
		{"go_net_dialcontext_method", "../../../testdata/source/taint/go/raw_socket/dialcontext", "raw_socket"},
		{"rust_fs_read_to_string", "../../../testdata/source/taint/rust/path_traversal/read_to_string", "path_traversal"},
		{"java_files_writestring", "../../../testdata/source/taint/java/path_traversal/writestring", "path_traversal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Run("vulnerable", func(t *testing.T) {
				res := analyze(t, c.base+"/vulnerable")
				if got := categoryFindings(res, c.category); len(got) == 0 {
					t.Fatalf("want a %s finding, got none among %+v", c.category, res.Findings)
				}
			})
			t.Run("fixed", func(t *testing.T) {
				res := analyze(t, c.base+"/fixed")
				if got := categoryFindings(res, c.category); len(got) != 0 {
					t.Fatalf("want no %s finding once the fix is applied, got %+v", c.category, got)
				}
			})
			t.Run("benign", func(t *testing.T) {
				res := analyze(t, c.base+"/benign")
				if got := categoryFindings(res, c.category); len(got) != 0 {
					t.Fatalf("want no %s finding when no tainted value reaches the call, got %+v", c.category, got)
				}
			})
		})
	}
}
