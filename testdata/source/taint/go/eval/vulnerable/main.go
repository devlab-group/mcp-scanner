package taintfixture

import "plugin"

// Go has no eval; loading and running arbitrary compiled code from a
// caller-controlled path is its equivalent dynamic-code-loading hazard
func LoadHandler(ctx Context, args LoadArgs) (string, error) {
	p, err := plugin.Open(args.PluginPath)
	if err != nil {
		return "", err
	}
	_ = p
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "load_plugin", Description: "Loads a plugin"}, LoadHandler)
}
