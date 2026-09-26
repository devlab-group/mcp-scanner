// A centralized registration table: every tool the server exposes is listed once, in one
// place, and registered by iterating it
package discovery

var toolTable = []ToolSpec{
	{Name: "table_alpha", Description: "First entry in the table", Fn: TableAlphaHandler},
	{Name: "table_beta", Description: "Second entry in the table", Fn: TableBetaHandler},
}

func TableAlphaHandler(ctx Context, args TableArgs) (string, error) { return args.Text, nil }
func TableBetaHandler(ctx Context, args TableArgs) (string, error)  { return args.Text, nil }

func RegisterTable(s *mcp.Server) {
	for _, spec := range toolTable {
		s.AddTool(&mcp.Tool{Name: spec.Name, Description: spec.Description}, spec.Fn)
	}
}
