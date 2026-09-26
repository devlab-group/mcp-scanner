; Plain JS has no decorator syntax in the grammar used here; kept for
; interface symmetry with typescript so the loader never special-cases it
(method_definition decorator: (decorator) @decorated)
(class_declaration decorator: (decorator) @decorated)
