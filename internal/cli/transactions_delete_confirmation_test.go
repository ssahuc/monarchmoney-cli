package cli

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/thedavidweng/monarchmoney-cli/internal/testutil"
)

type deleteEnvelope struct {
	OK   bool `json:"ok"`
	Data struct {
		Status           string `json:"status"`
		Deleted          bool   `json:"deleted"`
		TransactionID    string `json:"transaction_id"`
		PlannedMutations []struct {
			Operation  string `json:"operation"`
			ResourceID string `json:"resource_id"`
		} `json:"planned_mutations"`
	} `json:"data"`
	Error *struct {
		Code string `json:"code"`
	} `json:"error"`
	Meta struct {
		Command string `json:"command"`
	} `json:"meta"`
}

func runDeleteWith(t *testing.T, response string, setup func()) (deleteEnvelope, int, int) {
	t.Helper()
	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "session.json")
	exitCode := withWriteCommandTestDefaults(t, sessionPath, transactionsDeleteCmd)
	saveTestSession(t, sessionPath)
	if setup != nil {
		setup()
	}
	calls := 0
	http.DefaultTransport = testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return testutil.JSONResponse(response), nil
	})
	out := captureStdout(t, func() {
		transactionsDeleteCmd.Run(transactionsDeleteCmd, []string{"tx-1"})
	})
	var env deleteEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("output is not a JSON envelope: %q", out)
	}
	return env, *exitCode, calls
}

func TestTransactionsDeleteConfirmedSuccess(t *testing.T) {
	env, code, calls := runDeleteWith(t, `{"data":{"deleteTransaction":{"deleted":true,"errors":[]}}}`, nil)
	if code != 0 || !env.OK || calls != 1 {
		t.Fatalf("code=%d ok=%v calls=%d", code, env.OK, calls)
	}
	if !env.Data.Deleted || env.Data.TransactionID != "tx-1" || env.Data.Status != "deleted" || env.Meta.Command != "transactions.delete" {
		t.Fatalf("unexpected success data: %+v", env)
	}
}

func TestTransactionsDeleteRejectedIsDefinitive(t *testing.T) {
	env, code, _ := runDeleteWith(t, `{"data":{"deleteTransaction":{"deleted":false,"errors":[{"message":"no"}]}}}`, nil)
	if env.OK || env.Error == nil || env.Error.Code != "DELETE_REJECTED" || code != 11 {
		t.Fatalf("want DELETE_REJECTED exit 11, got code=%d env=%+v", code, env)
	}
}

func TestTransactionsDeleteContradictoryIsUnconfirmed(t *testing.T) {
	env, code, _ := runDeleteWith(t, `{"data":{"deleteTransaction":{"deleted":true,"errors":[{"message":"x"}]}}}`, nil)
	if env.OK || env.Error == nil || env.Error.Code != "DELETE_UNCONFIRMED" || code != 12 {
		t.Fatalf("want DELETE_UNCONFIRMED exit 12, got code=%d env=%+v", code, env)
	}
}

func TestTransactionsDeleteMissingDeletedIsUnconfirmed(t *testing.T) {
	env, _, _ := runDeleteWith(t, `{"data":{"deleteTransaction":{}}}`, nil)
	if env.OK || env.Error == nil || env.Error.Code != "DELETE_UNCONFIRMED" {
		t.Fatalf("want DELETE_UNCONFIRMED, got %+v", env)
	}
}

func TestTransactionsDeleteTopLevelGraphQLErrorIsNotDefinitive(t *testing.T) {
	env, _, _ := runDeleteWith(t, `{"errors":[{"message":"boom"}]}`, nil)
	if env.OK || env.Error == nil || env.Error.Code == "DELETE_REJECTED" || env.Error.Code == "" {
		t.Fatalf("top-level GraphQL error must fail without a definitive code, got %+v", env)
	}
}

func TestTransactionsDeleteWithoutConfirmSendsNoRequest(t *testing.T) {
	env, code, calls := runDeleteWith(t, `{}`, func() { confirm = false })
	if calls != 0 || env.Error == nil || env.Error.Code != "CONFIRMATION_REQUIRED" || code != 10 {
		t.Fatalf("want local CONFIRMATION_REQUIRED with no request, got calls=%d code=%d env=%+v", calls, code, env)
	}
}

func TestTransactionsDeleteReadOnlySendsNoRequest(t *testing.T) {
	env, code, calls := runDeleteWith(t, `{}`, func() { readOnly = true })
	if calls != 0 || env.Error == nil || env.Error.Code != "READ_ONLY_VIOLATION" || code != 4 {
		t.Fatalf("want local READ_ONLY_VIOLATION with no request, got calls=%d code=%d env=%+v", calls, code, env)
	}
}

func TestTransactionsDeleteDryRunSendsNoRequest(t *testing.T) {
	env, code, calls := runDeleteWith(t, `{}`, func() { dryRun = true; confirm = false })
	if calls != 0 || code != 0 || !env.OK || len(env.Data.PlannedMutations) != 1 || env.Data.PlannedMutations[0].ResourceID != "tx-1" {
		t.Fatalf("dry run must plan locally only, got calls=%d code=%d env=%+v", calls, code, env)
	}
}
