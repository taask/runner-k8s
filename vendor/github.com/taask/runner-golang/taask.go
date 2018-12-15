package taask

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cohix/simplcrypto"

	log "github.com/cohix/simplog"
	"github.com/pkg/errors"
	"github.com/taask/taask-server/model"
	"github.com/taask/taask-server/service"
	"google.golang.org/grpc"
)

// TaskHandler represents a handler that can handle a task
type TaskHandler func(*model.Task) (interface{}, error)

// Runner describes a runner
type Runner struct {
	runner  *model.Runner
	keypair *simplcrypto.KeyPair
	client  service.RunnerServiceClient
	handler TaskHandler
}

// NewRunner creates a new runner
func NewRunner(kind string, tags []string, handler TaskHandler) (*Runner, error) {
	modelRunner := &model.Runner{
		UUID: model.NewRunnerUUID(),
		Kind: kind,
		Tags: tags,
	}

	keypair, err := simplcrypto.GenerateNewKeyPair()
	if err != nil {
		return nil, errors.Wrap(err, "failed to GenerateNewKeyPair")
	}

	runner := &Runner{
		runner:  modelRunner,
		keypair: keypair,
		handler: handler,
	}

	return runner, nil
}

// ConnectAndRun connects to a taask-server, registers the runner, and runs
func (r *Runner) ConnectAndRun(joinCode, addr, port string) error {
	log.LogInfo(fmt.Sprintf("starting runner of kind %s", r.runner.Kind))

	conn, err := grpc.Dial(fmt.Sprintf("%s:%s", addr, port), grpc.WithInsecure())
	if err != nil {
		return errors.Wrap(err, "failed to Dial")
	}

	r.client = service.NewRunnerServiceClient(conn)

	challenge, err := r.auth(joinCode)
	if err != nil {
		return errors.Wrap(err, "failed to auth")
	}

	if err := r.run(challenge); err != nil {
		return errors.Wrap(err, "failed to run")
	}

	return nil
}

func (r *Runner) auth(joinCode string) ([]byte, error) {
	defer log.LogTrace("auth")()

	joinSig, err := r.keypair.Sign([]byte(joinCode))
	if err != nil {
		return nil, errors.Wrap(err, "failed to Sign")
	}

	authReq := &model.AuthRunnerRequest{
		PubKey:            r.keypair.SerializablePubKey(),
		JoinCodeSignature: joinSig,
	}

	resp, err := r.client.AuthRunner(context.Background(), authReq)
	if err != nil {
		return nil, errors.Wrap(err, "failed to AuthRunner")
	}

	challengeKeyJSON, err := r.keypair.Decrypt(resp.EncChallengeKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Decrypt challengeKey")
	}

	challengeKey, err := simplcrypto.SymKeyFromJSON(challengeKeyJSON)
	if err != nil {
		return nil, errors.Wrap(err, "failed to SymKeyFromJSON")
	}

	challenge, err := challengeKey.Decrypt(resp.EncChallenge)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Decrypt challenge")
	}

	return challenge, nil
}

func (r *Runner) run(challenge []byte) error {
	challengeSig, err := r.keypair.Sign(challenge)
	if err != nil {
		return errors.Wrap(err, "failed to Sign")
	}

	req := &model.RegisterRunnerRequest{
		UUID:               r.runner.UUID,
		Kind:               r.runner.Kind,
		Tags:               r.runner.Tags,
		ChallengeSignature: challengeSig,
	}

	log.LogInfo("registering with server...")

	stream, err := r.client.RegisterRunner(context.Background(), req)
	if err != nil {
		return errors.Wrap(err, "failed to RegisterRunner")
	}

	log.LogInfo("ready to receive tasks")

	for {
		task, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				log.LogError(errors.New("stream broken; terminating"))
				break
			}

			log.LogError(errors.Wrap(err, "stream error"))
			break
		}

		if task.UUID == "" {
			// an empty task is like a heartbeat, ignore it
			continue
		}

		log.LogInfo(fmt.Sprintf("received task with uuid %s", task.UUID))

		go func(handler TaskHandler, task *model.Task) {
			if err := r.sendUpdate(task, nil, nil); err != nil {
				log.LogError(errors.Wrap(err, "failed to sendUpdate"))
			}

			result, err := handler(task)
			if err != nil {
				if err := r.sendUpdate(task, nil, err); err != nil {
					log.LogError(errors.Wrap(err, "failed to sendUpdate"))
				}

				return
			}

			if err := r.sendUpdate(task, result, nil); err != nil {
				log.LogError(errors.Wrap(err, "failed to sendUpdate"))
			}
		}(r.handler, task)
	}

	return nil
}

func (r *Runner) sendUpdate(task *model.Task, result interface{}, taskErr error) error {
	update := &model.TaskUpdate{
		UUID:        task.UUID,
		ResultToken: task.Meta.ResultToken,
	}

	if result == nil && taskErr == nil {
		update.Status = model.TaskStatusRunning
	} else {
		resultSymKey, err := simplcrypto.GenerateSymKey()
		if err != nil {
			return errors.Wrap(err, "failed to GenerateSymKey")
		}

		resultPubKey, err := simplcrypto.KeyPairFromSerializedPubKey(task.Meta.ResultPubKey)
		if err != nil {
			return errors.Wrap(err, "failed to KeyPairFromSerializedPubKey")
		}

		encResultKey, err := resultPubKey.Encrypt(resultSymKey.JSON())
		if err != nil {
			return errors.Wrap(err, "failed to Encrypt resultSymKey")
		}

		var encResult *simplcrypto.Message

		if result == nil && taskErr != nil {
			update.Status = model.TaskStatusFailed

			encResult, err = resultSymKey.Encrypt([]byte(taskErr.Error()))
			if err != nil {
				return errors.Wrap(err, "failed to Encrypt error result")
			}
		} else if result != nil && taskErr == nil {
			update.Status = model.TaskStatusCompleted

			resultJSON, err := json.Marshal(result)
			if err != nil {
				return errors.Wrap(err, "failed to Marshal result")
			}

			encResult, err = resultSymKey.Encrypt(resultJSON)
			if err != nil {
				return errors.Wrap(err, "failed to Encrypt result")
			}
		}

		update.EncResult = encResult
		update.EncResultSymKey = encResultKey
	}

	if _, err := r.client.UpdateTask(context.Background(), update); err != nil {
		return errors.Wrap(err, "failed to UpdateTask")
	}

	return nil
}
