package service

import "context"

type auditContextKey struct{}

type auditRequestMetadata struct {
	SourceIP  string
	UserAgent string
	RequestID string
}

// WithRequestMetadata carries the request boundary into service methods so
// audit rows retain the real network and correlation information. Background
// workers can omit it and Audit will fall back to the authenticated session.
func WithRequestMetadata(ctx context.Context, sourceIP, userAgent, requestID string) context.Context {
	return context.WithValue(ctx, auditContextKey{}, auditRequestMetadata{SourceIP: sourceIP, UserAgent: userAgent, RequestID: requestID})
}

func auditMetadataFromContext(ctx context.Context) auditRequestMetadata {
	metadata, _ := ctx.Value(auditContextKey{}).(auditRequestMetadata)
	return metadata
}
