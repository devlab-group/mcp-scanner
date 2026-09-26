package protocol

// Rule IDs are stable report and suppression keys
const (
	RuleVersionMissing     = "protocol.version-missing"
	RuleVersionUnknown     = "protocol.version-unknown"
	RuleCapabilityMismatch = "protocol.capability-mismatch"

	RuleNameCharset            = "protocol.name-charset"
	RuleNameDuplicate          = "protocol.name-duplicate"
	RuleNameCollision          = "protocol.name-collision"
	RuleMissingDescription     = "protocol.missing-description"
	RuleSchemaInvalid          = "protocol.schema-invalid"
	RuleSchemaRequiredMismatch = "protocol.schema-required-mismatch"
	RuleOutputSchemaInvalid    = "protocol.output-schema-invalid"
	RuleAnnotationConflict     = "protocol.annotation-conflict"

	RuleResourceURIUnsafe = "protocol.resource-uri-unsafe"
	RuleInstructionsLarge = "protocol.instructions-large"

	RuleCrossOriginRedirect = "protocol.cross-origin-redirect"

	RuleProbeUnexpectedAnswer   = "protocol.probe-unexpected-answer"
	RuleProbeLeaksInternals     = "protocol.probe-leaks-internals"
	RuleProbeConnectionDied     = "protocol.probe-connection-died"
	RuleProbeAcceptedUnanswered = "protocol.probe-accepted-unanswered"
)
