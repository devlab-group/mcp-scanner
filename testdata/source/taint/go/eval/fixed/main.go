package taintfixture

import "plugin"

// LoadHandler now maps the requested name to one of a fixed set of literal
// plugin paths instead of loading whatever path the caller provides
func LoadHandler(ctx Context, args LoadArgs) (string, error) {
	var path string
	switch args.PluginName {
	case "logging":
		path = "/opt/plugins/logging.so"
	case "metrics":
		path = "/opt/plugins/metrics.so"
	default:
		return "", errUnknownPlugin
	}
	p, err := plugin.Open(path)
	if err != nil {
		return "", err
	}
	_ = p
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "load_plugin", Description: "Loads one of a fixed set of known plugins"}, LoadHandler)
}
