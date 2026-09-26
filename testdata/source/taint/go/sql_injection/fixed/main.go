package taintfixture

// LookupHandler now binds the id as a parameter instead of concatenating
// it into the query text: the query string itself is a fixed literal, and
// the tainted value only ever reaches the database as a bound parameter
func LookupHandler(ctx Context, args LookupArgs) (string, error) {
	rows, err := db.Query("SELECT * FROM users WHERE id = ?", args.ID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "lookup", Description: "Looks up a user by id"}, LookupHandler)
}
