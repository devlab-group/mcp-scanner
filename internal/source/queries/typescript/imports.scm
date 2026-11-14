(import_statement) @import
; The arguments are read in Go: a pattern that reaches into them keeps a match pending for
; every enclosing call while the cursor walks them, quadratic in the nesting depth
(call_expression
  function: (identifier) @require.function
  (#eq? @require.function "require")) @require
