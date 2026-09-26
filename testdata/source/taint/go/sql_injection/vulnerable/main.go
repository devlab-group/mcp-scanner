package taintfixture

func LookupHandler(ctx Context, args LookupArgs) (string, error) {
	rows, err := db.Query("SELECT * FROM users WHERE id = " + args.ID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "lookup", Description: "Looks up a user by id"}, LookupHandler)
}
