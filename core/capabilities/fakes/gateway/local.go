package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	httptypedapi "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/triggers/http"
)

type TriggerInput []byte

func (t *TriggerInput) UnmarshalJSON(bytes []byte) error {
	*t = bytes
	return nil
}

type BaseJsonRpc struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      string `json:"id"`
	Method  string `json:"method"`
}

type JsonRpcRequest struct {
	BaseJsonRpc
	Params struct {
		Input    TriggerInput `json:"input"`
		Workflow struct {
			WorkflowID string `json:"workflowID"`
		} `json:"workflow"`
	} `json:"params"`
}

type JsonRpcResponse struct {
	BaseJsonRpc
	Result struct {
		WorkflowID          string `json:"workflow_id"`
		WorkflowExecutionID string `json:"workflow_execution_id"`
		Status              string `json:"status"`
	} `json:"result"`
}

type Config struct {
	Port uint16
}

type LocalGateway struct {
	config Config
}

func NewLocalGateway(config Config) *LocalGateway {
	return &LocalGateway{config: config}
}

func (g *LocalGateway) ListenForTriggerPayload(ctx context.Context) (*httptypedapi.Payload, error) {
	payloadCh := make(chan *httptypedapi.Payload, 1)
	errorCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		input, err := parseRequest(r)
		if err != nil {
			http.Error(w, fmt.Sprintf("error processing request: %v", err), http.StatusBadRequest)
			return
		}

		payloadCh <- &httptypedapi.Payload{
			Input: input.Params.Input,
		}
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", g.config.Port),
		Handler: mux,
	}
	defer server.Close()

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorCh <- err
		}
	}()

	select {
	case payload := <-payloadCh:
		return payload, nil
	case err := <-errorCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func parseRequest(req *http.Request) (*JsonRpcRequest, error) {
	if req.Method != http.MethodPost {
		return nil, errors.New("gateway expects POST request")
	}

	authHeader := req.Header.Get("Authorization")
	if strings.TrimSpace(authHeader) == "" {
		return nil, errors.New("authorization header is missing")
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	if err := validateBearerJWT(authHeader, body); err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	var input JsonRpcRequest
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, fmt.Errorf("failed to parse request body: %w", err)
	}

	return &input, nil
}
