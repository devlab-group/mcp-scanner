// The handler implementation lives in its own file, separate from the
// registration call that references it by name
package discovery

func CrossFileHandler(ctx Context, args CrossFileArgs) (string, error) {
	return args.Text, nil
}
