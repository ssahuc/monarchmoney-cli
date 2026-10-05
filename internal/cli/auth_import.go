package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/thedavidweng/monarchmoney-cli/internal/auth"
	"github.com/thedavidweng/monarchmoney-cli/internal/errors"
	"github.com/thedavidweng/monarchmoney-cli/internal/graphql"
	"github.com/thedavidweng/monarchmoney-cli/internal/output"
)

const importSessionInstructions = `Log into https://app.monarch.com in your browser, open the developer tools
Network tab, select any request to api.monarch.com/graphql, and copy the
session_id and csrftoken values from its Cookie request header.
`

var importSessionCmd = &cobra.Command{
	Use:   "import-session",
	Short: "Use a Monarch session from your browser login",
	Long: `Store the Monarch session you established by logging into https://app.monarch.com in your browser, for use when password login is blocked.
On a terminal it prompts (hidden) for the session_id and csrftoken cookie values; otherwise it reads a Cookie header from stdin and keeps only those two cookies.
The session is checked against Monarch before it is saved, and nothing is saved if Monarch rejects it.
Secrets are never accepted as flags. Logging out of Monarch in the browser ends this session too.`,
	Example: `  monarch auth import-session
  pbpaste | monarch auth import-session --json`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		renderer := output.NewRenderer(nil, nil, jsonMode, pretty)

		creds, cliErr := readBrowserSession()
		if cliErr != nil {
			handleError(renderer, "auth.import-session", cliErr, start)
			return
		}

		if !jsonMode {
			fmt.Println("Validating session with Monarch...")
		}
		identity, err := fetchIdentity(cmd.Context(), creds)
		if err != nil {
			handleError(renderer, "auth.import-session", rejectedImport(err), start)
			return
		}

		now := time.Now()
		sess := &auth.Session{
			Profile:    profile,
			Email:      identity.Email,
			CreatedAt:  now,
			UpdatedAt:  now,
			AuthMethod: auth.AuthMethodBrowserSession,
			SessionID:  creds.SessionID,
			CSRFToken:  creds.CSRFToken,
		}
		if err := newSessionStore(defaultSessionPath()).Save(sess); err != nil {
			handleError(renderer, "auth.import-session", errors.New(errors.InternalError, "failed to save session", errors.CatInternal, false, err), start)
			return
		}

		if jsonMode {
			env := output.NewEnvelope("auth.import-session", profile, output.SchemaVersion, requestID, map[string]any{
				"status":       "session imported",
				"auth_method":  auth.AuthMethodBrowserSession,
				"email":        sess.Email,
				"profile":      sess.Profile,
				"created_at":   sess.CreatedAt,
				"session_path": defaultSessionPath(),
			}, time.Since(start))
			renderer.RenderSuccess(env)
		} else {
			fmt.Printf("Monarch browser session saved for %s.\n", sess.Email)
			fmt.Printf("Session saved to: %s\n", defaultSessionPath())
		}
	},
}

func readBrowserSession() (graphql.SessionAuth, *errors.Error) {
	if !stdinIsTerminal() {
		input, err := readStdin()
		if err != nil {
			return graphql.SessionAuth{}, errors.New(errors.InternalError, "failed to read Cookie header from stdin", errors.CatInternal, false, err)
		}
		sessionID, csrf, err := auth.ParseSessionCookies(string(input))
		if err != nil {
			return graphql.SessionAuth{}, errors.New(errors.InvalidArguments, err.Error(), errors.CatValidation, false, nil)
		}
		return graphql.SessionAuth{SessionID: sessionID, CSRFToken: csrf}, nil
	}

	if jsonMode {
		return graphql.SessionAuth{}, errors.New(errors.InvalidArguments, "--json never prompts; pipe the Cookie header on stdin instead", errors.CatValidation, false, nil)
	}

	fmt.Print(importSessionInstructions)
	values := map[string]string{}
	for _, name := range []string{"session_id", "csrftoken"} {
		fmt.Printf("%s (hidden): ", name)
		raw, err := readPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return graphql.SessionAuth{}, errors.New(errors.InternalError, "failed to read "+name, errors.CatInternal, false, err)
		}
		value := strings.Trim(strings.TrimPrefix(strings.TrimSpace(string(raw)), name+"="), `"`)
		if value == "" {
			return graphql.SessionAuth{}, errors.New(errors.InvalidArguments, name+" is required", errors.CatValidation, false, nil)
		}
		values[name] = value
	}
	return graphql.SessionAuth{SessionID: values["session_id"], CSRFToken: values["csrftoken"]}, nil
}

// rejectedImport reports a failed validation as a rejected import, never as the stored
// session expiring, because the stored session (if any) is left untouched.
func rejectedImport(err error) *errors.Error {
	cliErr, ok := err.(*errors.Error)
	if !ok {
		return errors.New(errors.InternalError, "failed to validate session", errors.CatInternal, false, err)
	}
	if cliErr.Code == errors.AuthSessionExpired {
		return errors.New(errors.AuthRequired, "Monarch rejected the imported session; nothing was saved. Copy fresh session_id and csrftoken values from a logged-in browser", errors.CatAuth, false, nil)
	}
	return cliErr
}
