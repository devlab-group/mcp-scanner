(import_statement) @import
(call_expression
  function: (identifier) @require.function
  arguments: (arguments (string) @require.path)
  (#eq? @require.function "require")) @require
