package op

// AccessTokenAudienceRequest is an optional interface which may be implemented by a
// [TokenRequest] to give the access token a different audience than the ID token.
//
// GetAudience of [TokenRequest] is used for the audience of both tokens. With resource
// indicators ([RFC 8707]) the access token is addressed to the requested resources,
// whereas the ID token is addressed to the client and should not carry them. When a
// request implements this interface, GetAccessTokenAudience is used for the audience
// of JWT access tokens and GetAudience remains the audience of the ID token.
//
// Carried from zitadel/oidc#955 (commit 864f05c) on the vidp branch of
// github.com/at15/oidc; drop it when a release has it.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
type AccessTokenAudienceRequest interface {
	GetAccessTokenAudience() []string
}

// AccessTokenAudience returns the audience of an access token issued for request:
// the result of GetAccessTokenAudience if request implements
// [AccessTokenAudienceRequest], and of GetAudience otherwise.
//
// It is used for JWT access tokens, and may be used by [Storage] implementations to
// record the audience of opaque access tokens, so that both token types agree.
func AccessTokenAudience(request TokenRequest) []string {
	if audienceRequest, ok := request.(AccessTokenAudienceRequest); ok {
		return audienceRequest.GetAccessTokenAudience()
	}
	return request.GetAudience()
}
