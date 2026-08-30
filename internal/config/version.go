package config

// Build metadata injected by goreleaser via -ldflags -X.
var (
	Version   = "dev"
	Revision  = "unknown"
	BuildTime = "unknown"
)
