package ossignserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Well-known environment variables used by CI providers to issue OIDC tokens.
const (
	// GitHub Actions (requires `permissions: id-token: write`)
	envGitHubRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	envGitHubRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"

	// GitLab CI (requires an `id_tokens:` entry in the job definition)
	envGitLabIDToken = "OSSIGN_ID_TOKEN"

	// Generic override, used by Provider "env" when IDTokenEnv is not set.
	envGenericIDToken = "OSSIGN_ID_TOKEN"
)

// GetIDToken obtains an OIDC identity token from the CI environment according
// to opts.Provider.
func GetIDToken(ctx context.Context, opts Options) (string, error) {
	audience := opts.Audience
	if audience == "" {
		audience = opts.URL
	}

	provider := strings.ToLower(opts.Provider)
	switch provider {
	case "static":
		if opts.IDToken == "" {
			return "", fmt.Errorf("ossignServer.idToken is required when provider is \"static\"")
		}
		return opts.IDToken, nil

	case "env":
		name := opts.IDTokenEnv
		if name == "" {
			name = envGenericIDToken
		}
		tok := os.Getenv(name)
		if tok == "" {
			return "", fmt.Errorf("environment variable %s is empty, no OIDC token available", name)
		}
		return tok, nil

	case "github":
		return githubIDToken(ctx, audience)

	case "gitlab":
		name := opts.IDTokenEnv
		if name == "" {
			name = envGitLabIDToken
		}
		tok := os.Getenv(name)
		if tok == "" {
			return "", fmt.Errorf("environment variable %s is empty; add an `id_tokens:` section with `aud: %s` to your GitLab job", name, audience)
		}
		return tok, nil

	case "", "auto":
		if opts.IDToken != "" {
			return opts.IDToken, nil
		}
		if opts.IDTokenEnv != "" {
			if tok := os.Getenv(opts.IDTokenEnv); tok != "" {
				return tok, nil
			}
		}
		if os.Getenv(envGitHubRequestURL) != "" && os.Getenv(envGitHubRequestToken) != "" {
			return githubIDToken(ctx, audience)
		}
		if tok := os.Getenv(envGenericIDToken); tok != "" {
			return tok, nil
		}
		return "", fmt.Errorf("could not detect an OIDC token source. On GitHub Actions make sure the job has `permissions: id-token: write`; otherwise set ossignServer.provider")

	default:
		return "", fmt.Errorf("unknown ossignServer.provider %q (expected auto, github, gitlab, env or static)", opts.Provider)
	}
}

// githubIDToken requests an OIDC token from the GitHub Actions token service.
func githubIDToken(ctx context.Context, audience string) (string, error) {
	reqURL := os.Getenv(envGitHubRequestURL)
	reqToken := os.Getenv(envGitHubRequestToken)
	if reqURL == "" || reqToken == "" {
		return "", fmt.Errorf("%s / %s not set; the job needs `permissions: id-token: write`", envGitHubRequestURL, envGitHubRequestToken)
	}

	u, err := url.Parse(reqURL)
	if err != nil {
		return "", fmt.Errorf("invalid %s: %w", envGitHubRequestURL, err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+reqToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting GitHub OIDC token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("requesting GitHub OIDC token: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decoding GitHub OIDC token response: %w", err)
	}
	if out.Value == "" {
		return "", fmt.Errorf("GitHub OIDC token response did not contain a token")
	}
	return out.Value, nil
}
