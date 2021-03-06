package brain

import (
	"net/http"

	"github.com/cohix/simplcrypto"
	log "github.com/cohix/simplog"
	"github.com/pkg/errors"
	"github.com/taask/taask-server/auth"
	"github.com/taask/taask-server/metrics"
	"github.com/taask/taask-server/model"
	"github.com/taask/taask-server/model/validator"
	"github.com/taask/taask-server/schedule"
	"github.com/taask/taask-server/storage"
	"github.com/taask/taask-server/update"
)

// Manager is the facade for the subsystem managers (schedule, storage, update, auth)
type Manager struct {
	scheduler  *schedule.Manager
	storage    storage.Manager
	runnerAuth *auth.RunnerAuthManager
	Updater    *update.Manager

	metrics *metrics.Manager
}

// NewManager creates a new manager
func NewManager(joinCode string, storage storage.Manager) *Manager {
	metrics, err := metrics.NewManager()
	if err != nil {
		log.LogError(errors.Wrap(err, "failed to metrics.NewManager"))
		return nil
	}

	updater := update.NewManager(storage, metrics)

	scheduler := schedule.NewManager(updater)
	go scheduler.Start()

	runnerAuth, err := auth.NewRunnerAuthManager(joinCode)
	if err != nil {
		log.LogError(errors.Wrap(err, "failed to NewRunnerAuthManager"))
		return nil
	}

	return &Manager{
		scheduler:  scheduler,
		storage:    storage,
		runnerAuth: runnerAuth,
		Updater:    updater,
		metrics:    metrics,
	}
}

// AuthRunner allows a runner to auth
func (m *Manager) AuthRunner(pubKey *simplcrypto.SerializablePubKey, joinCodeSig *simplcrypto.Signature) (*auth.EncRunnerAuth, error) {
	return m.runnerAuth.AttemptAuth(pubKey, joinCodeSig)
}

// RegisterRunner registers a runner with the manager's scheduler
func (m *Manager) RegisterRunner(runner *model.Runner, challengeSignature *simplcrypto.Signature) error {
	if err := m.runnerAuth.CheckRunnerAuth(runner.UUID, challengeSignature); err != nil {
		return errors.Wrap(err, "failed to CheckRunnerChallenge")
	}

	m.scheduler.RegisterRunner(runner)

	return nil
}

// UnregisterRunner unregisters a runner
func (m *Manager) UnregisterRunner(runner *model.Runner) {
	if err := m.scheduler.UnregisterRunner(runner.Kind, runner.UUID); err != nil {
		log.LogError(errors.Wrap(err, "failed to UnregisterRunner"))
	}

	if err := m.runnerAuth.DeleteRunnerKey(runner.UUID); err != nil {
		log.LogError(errors.Wrap(err, "failed to DeleteRunnerKey"))
	}
}

// EncryptTaskKeyForRunner encrypts a task key for a runner
func (m *Manager) EncryptTaskKeyForRunner(runnerUUID string, encTaskKey *simplcrypto.Message) (*simplcrypto.Message, error) {
	encKey, err := m.runnerAuth.ReEncryptTaskKey(runnerUUID, encTaskKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ReEncryptTaskKey")
	}

	return encKey, nil
}

// GetMasterRunnerPubKey returns the master runner pubkey
func (m *Manager) GetMasterRunnerPubKey() *simplcrypto.SerializablePubKey {
	return m.runnerAuth.RunnerMasterPubKey()
}

// ScheduleTask schedules and persists a task
func (m *Manager) ScheduleTask(task *model.Task) (string, error) {
	if result := validator.ValidateTask(task); !result.Ok() {
		return "", errors.Wrap(errors.New(result.String()), "failed to ValidateTask")
	}

	task.UUID = model.NewTaskUUID()
	task.Status = ""      // clear this in case it was set
	task.Meta.Version = 0 // set this to 0
	if task.Meta.TimeoutSeconds == 0 {
		task.Meta.TimeoutSeconds = 600 // 10m default
	}

	if err := m.storage.Add(*task); err != nil {
		return "", errors.Wrap(err, "failed to storage.Add")
	}

	// we do a manual update to waiting to ensure the metrics catch the new task
	update, err := task.Update(model.TaskUpdate{Status: model.TaskStatusWaiting})
	if err != nil {
		return "", errors.Wrap(err, "failed to task.Update")
	}

	m.Updater.UpdateTask(update)

	go m.scheduler.ScheduleTask(task)

	return task.UUID, nil
}

// GetTask gets a task from storage
func (m *Manager) GetTask(uuid string) (*model.Task, error) {
	return m.storage.Get(uuid)
}

// UpdateTask applies a task update from a runner
func (m *Manager) UpdateTask(update model.TaskUpdate) error {
	if update.RunnerUUID != "" {
		return errors.New("RunnerUUID is immutable")
	}

	if update.RetrySeconds != 0 {
		return errors.New("RetrySeconds is immutable")
	}

	m.Updater.UpdateTask(update)

	return nil
}

// JoinCode returns the runner join code
func (m *Manager) JoinCode() string {
	return m.runnerAuth.JoinCode
}

// MetricsHandler returns the http handler for metrics scraping
func (m *Manager) MetricsHandler() http.Handler {
	return m.metrics.Handler()
}
