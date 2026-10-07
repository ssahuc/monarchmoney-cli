package monarch

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/thedavidweng/monarchmoney-cli/internal/errors"
	"github.com/thedavidweng/monarchmoney-cli/internal/graphql"
)

// TestDeleteTransactionConfirmation pins the deletion-confirmation contract
// that household-finance SPEC-003 §5.1 depends on: success only when Monarch
// returns deleted == true with no payload errors; DELETE_REJECTED only for a
// well-formed deleted == false; DELETE_UNCONFIRMED for everything ambiguous.
func TestDeleteTransactionConfirmation(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    errors.Code // "" means success
	}{
		{"deleted true, empty errors", `{"deleteTransaction":{"deleted":true,"errors":[]}}`, ""},
		{"deleted true, no errors field", `{"deleteTransaction":{"deleted":true}}`, ""},
		{"deleted true, null errors", `{"deleteTransaction":{"deleted":true,"errors":null}}`, ""},
		{"deleted false, empty errors", `{"deleteTransaction":{"deleted":false,"errors":[]}}`, errors.DeleteRejected},
		{"deleted false, no errors field", `{"deleteTransaction":{"deleted":false}}`, errors.DeleteRejected},
		{"deleted false, with errors", `{"deleteTransaction":{"deleted":false,"errors":[{"message":"not allowed"}]}}`, errors.DeleteRejected},
		{"deleted true, with errors (contradictory)", `{"deleteTransaction":{"deleted":true,"errors":[{"message":"x"}]}}`, errors.DeleteUnconfirmed},
		{"missing deleted", `{"deleteTransaction":{"errors":[]}}`, errors.DeleteUnconfirmed},
		{"empty payload object", `{"deleteTransaction":{}}`, errors.DeleteUnconfirmed},
		{"null deleted", `{"deleteTransaction":{"deleted":null}}`, errors.DeleteUnconfirmed},
		{"string deleted", `{"deleteTransaction":{"deleted":"true"}}`, errors.DeleteUnconfirmed},
		{"numeric deleted", `{"deleteTransaction":{"deleted":1}}`, errors.DeleteUnconfirmed},
		{"null payload", `{"deleteTransaction":null}`, errors.DeleteUnconfirmed},
		{"missing payload", `{}`, errors.DeleteUnconfirmed},
		{"legacy ok-only payload", `{"deleteTransaction":{"ok":true}}`, errors.DeleteUnconfirmed},
		{"malformed errors with deleted false", `{"deleteTransaction":{"deleted":false,"errors":"bad"}}`, errors.DeleteUnconfirmed},
		{"malformed errors with deleted true", `{"deleteTransaction":{"deleted":true,"errors":{"message":"x"}}}`, errors.DeleteUnconfirmed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var client *mockClient
			client = &mockClient{
				token: "token-123",
				handler: func(req *graphql.Request, result any) error {
					assertReq(t, req, "Common_DeleteTransactionMutation")
					return client.respond(result, tc.payload)
				},
			}
			err := NewService(client).DeleteTransaction(context.Background(), "tx-1")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("DeleteTransaction() error = %v, want success", err)
				}
				return
			}
			var e *errors.Error
			if !stderrors.As(err, &e) || e.Code != tc.want {
				t.Fatalf("DeleteTransaction() error = %v, want code %s", err, tc.want)
			}
		})
	}
}

// A transport or GraphQL-level failure is passed through unchanged: it is
// never reported as a definitive DELETE_REJECTED.
func TestDeleteTransactionTransportFailureIsNotDefinitive(t *testing.T) {
	client := &mockClient{
		token: "token-123",
		handler: func(req *graphql.Request, result any) error {
			return errors.New(errors.NetworkTimeout, "timeout", errors.CatNetwork, false, nil)
		},
	}
	err := NewService(client).DeleteTransaction(context.Background(), "tx-1")
	var e *errors.Error
	if !stderrors.As(err, &e) || e.Code != errors.NetworkTimeout {
		t.Fatalf("DeleteTransaction() error = %v, want NETWORK_TIMEOUT passed through", err)
	}
	if e.Code == errors.DeleteRejected {
		t.Fatal("transport failure must not be definitive")
	}
}
