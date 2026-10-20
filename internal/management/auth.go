package management

import "net/http"

const roleAdmin = "Covee.Admin"
const roleReader = "Covee.Reader"

// Actor is an authenticated identity, never a credential. Issuer and subject
// identify an OIDC user; display names have no authorization significance.
type Actor struct {
	Type    string `json:"type"`
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject"`
	Name    string `json:"name,omitempty"`
	Role    string `json:"role"`
}

type authContextKey struct{}

func localActor() Actor {
	return Actor{Type: "token", Subject: "local-admin", Name: "Local administrator", Role: roleAdmin}
}

func requestSession(r *http.Request) session {
	sess, _ := r.Context().Value(authContextKey{}).(session)
	return sess
}

func sessionResponse(sess session) map[string]any {
	return map[string]any{
		"authenticated": true,
		"csrfToken":     sess.csrf,
		"user":          sess.actor,
		"permissions":   map[string]bool{"canRead": true, "canWrite": sess.actor.Role == roleAdmin},
	}
}
