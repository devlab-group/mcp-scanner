package model

import "testing"

func TestOnlyStdioTargetsCarryACommand(t *testing.T) {
	base := map[TargetKind]Target{
		TargetRemote:  {Kind: TargetRemote, URL: "https://mcp.example.com/mcp"},
		TargetStatic:  {Kind: TargetStatic, Path: "snap.json"},
		TargetSource:  {Kind: TargetSource, Path: "."},
		TargetPackage: {Kind: TargetPackage, Ecosystem: "npm", Package: "left-pad"},
	}
	for kind, tgt := range base {
		if err := tgt.Validate(); err != nil {
			t.Fatalf("%s target without a command: %v", kind, err)
		}
		withCmd := tgt
		withCmd.Command = "/usr/bin/id"
		if err := withCmd.Validate(); err == nil {
			t.Errorf("%s target with a command was accepted", kind)
		}
		withArgs := tgt
		withArgs.Args = []string{"-u"}
		if err := withArgs.Validate(); err == nil {
			t.Errorf("%s target with args was accepted", kind)
		}
		withEnv := tgt
		withEnv.Env = map[string]string{"PATH": "/tmp"}
		if err := withEnv.Validate(); err == nil {
			t.Errorf("%s target with env was accepted", kind)
		}
	}

	stdio := Target{Kind: TargetStdio, Command: "python3", Args: []string{"server.py"}, Env: map[string]string{"X": "1"}}
	if err := stdio.Validate(); err != nil {
		t.Fatalf("stdio target with a command, args and env: %v", err)
	}
}
