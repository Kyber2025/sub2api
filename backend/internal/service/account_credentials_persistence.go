package service

import (
	"context"
	"strconv"
	"time"
)

type accountCredentialsUpdater interface {
	UpdateCredentials(ctx context.Context, id int64, credentials map[string]any) error
}

func persistAccountCredentials(ctx context.Context, repo AccountRepository, account *Account, credentials map[string]any) error {
	if repo == nil || account == nil {
		return nil
	}

	account.Credentials = cloneCredentials(credentials)
	if updater, ok := any(repo).(accountCredentialsUpdater); ok {
		return updater.UpdateCredentials(ctx, account.ID, account.Credentials)
	}
	return repo.Update(ctx, account)
}

func cloneCredentials(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// ParseCredentialExpiresAt extracts the token expiry time from a credentials
// map. Different platform OAuth services serialize `expires_at` in different
// formats:
//   - Unix seconds as JSON number (Go unmarshals to float64)
//   - Unix seconds as string (e.g., antigravity_oauth_service.BuildAccountCredentials)
//   - RFC3339 string (e.g., openai_oauth_service.BuildAccountCredentials)
//
// Returns nil when the value is missing, blank, or unparseable. Caller is
// expected to ignore nil results (i.e. leave the existing ExpiresAt column
// untouched) — never silently zero out a valid timestamp.
//
// This helper exists because the top-level accounts.expires_at column and the
// credentials JSON's expires_at field can drift after a token refresh / re-auth
// if only the credentials map is written. The account_expiry_service sweeper
// reads the column and will erroneously auto-pause an account that holds a
// fresh credentials.expires_at but a stale column value.
func ParseCredentialExpiresAt(creds map[string]any) *time.Time {
	if creds == nil {
		return nil
	}
	raw, ok := creds["expires_at"]
	if !ok || raw == nil {
		return nil
	}
	return parseExpiryValue(raw)
}

func parseExpiryValue(raw any) *time.Time {
	switch v := raw.(type) {
	case string:
		s := v
		if s == "" {
			return nil
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			t := time.Unix(n, 0)
			return &t
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return &t
		}
		return nil
	case float64:
		if v > 0 {
			t := time.Unix(int64(v), 0)
			return &t
		}
	case float32:
		if v > 0 {
			t := time.Unix(int64(v), 0)
			return &t
		}
	case int64:
		if v > 0 {
			t := time.Unix(v, 0)
			return &t
		}
	case int:
		if v > 0 {
			t := time.Unix(int64(v), 0)
			return &t
		}
	}
	return nil
}
