// The SDK package is imported under an alias; registration must still be
// found by the method name, not by the literal package identifier
package discovery

import mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

func AliasedHandler(ctx Context, args AliasedArgs) (string, error) { return args.Text, nil }

func RegisterAliased(s *mcpsdk.Server) {
	s.AddTool(&mcpsdk.Tool{Name: "aliased_echo", Description: "Registered through an aliased SDK import"}, AliasedHandler)
}
