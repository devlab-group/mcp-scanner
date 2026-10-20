package client

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/devlab-group/mcp-scanner/internal/mcp/discovery"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// LoadSnapshotBytes parses a snapshot the caller has already read. Bounding that read is
// the caller's job: a snapshot file is somebody else's output, so reading it whole before
// parsing is an unbounded read of an attacker-adjacent file.
func LoadSnapshotBytes(data []byte, name string) (*model.Snapshot, error) {
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", name, err)
	}
	if probe.SchemaVersion != "" {
		var s model.Snapshot
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("parsing snapshot %s: %w", name, err)
		}
		return &s, nil
	}
	// No schema_version
	if s, err := decodeStrictSnapshot(data); err == nil && !emptySnapshot(s) {
		return s, nil
	}
	return convertPlainDoc(data, name)
}

// decodeStrictSnapshot decodes data as model.Snapshot with unknown fields
// refused, which is what makes it a test of shape rather than a decode that
// always succeeds
func decodeStrictSnapshot(data []byte) (*model.Snapshot, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s model.Snapshot
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

func emptySnapshot(s *model.Snapshot) bool {
	return s == nil || (len(s.Tools) == 0 && len(s.Prompts) == 0 && len(s.Resources) == 0 &&
		len(s.Templates) == 0 && s.Instructions == "")
}

// plainDoc is the shape of a bare MCP discovery dump: the same field names a
// client would receive over the wire, not the scanner's own snake_case
// schema
type plainDoc struct {
	ServerInfo        *mcp.Implementation     `json:"serverInfo"`
	ProtocolVersion   string                  `json:"protocolVersion"`
	Instructions      string                  `json:"instructions"`
	Capabilities      *mcp.ServerCapabilities `json:"capabilities"`
	Tools             []*mcp.Tool             `json:"tools"`
	Prompts           []*mcp.Prompt           `json:"prompts"`
	Resources         []*mcp.Resource         `json:"resources"`
	ResourceTemplates []*mcp.ResourceTemplate `json:"resourceTemplates"`
}

func convertPlainDoc(data []byte, path string) (*model.Snapshot, error) {
	var doc plainDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s as an MCP document: %w", path, err)
	}

	snap := &model.Snapshot{
		SchemaVersion:   model.SchemaVersion,
		ProtocolVersion: doc.ProtocolVersion,
		Instructions:    doc.Instructions,
		Transport:       model.TransportInfo{Kind: "static"},
	}
	if doc.ServerInfo != nil {
		snap.ServerName = doc.ServerInfo.Name
		snap.ServerVersion = doc.ServerInfo.Version
		snap.ServerTitle = doc.ServerInfo.Title
	}
	if doc.Capabilities != nil {
		snap.Capabilities = discovery.ToMap(doc.Capabilities)
	}
	for _, t := range doc.Tools {
		snap.Tools = append(snap.Tools, discovery.ToolInfo(t))
	}
	for _, p := range doc.Prompts {
		snap.Prompts = append(snap.Prompts, discovery.PromptInfo(p))
	}
	for _, r := range doc.Resources {
		snap.Resources = append(snap.Resources, discovery.ResourceInfo(r))
	}
	for _, rt := range doc.ResourceTemplates {
		snap.Templates = append(snap.Templates, discovery.TemplateInfo(rt))
	}

	if len(snap.Tools) == 0 && len(snap.Prompts) == 0 && len(snap.Resources) == 0 &&
		len(snap.Templates) == 0 && snap.Instructions == "" {
		return nil, fmt.Errorf("%s does not look like an MCP snapshot or document: no tools, prompts, resources or instructions", path)
	}
	return snap, nil
}
