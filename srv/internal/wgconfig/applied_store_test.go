package wgconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"wireguard-panel/internal/model"
)

func TestSettledReadWaitsForInterfaceOperation(t *testing.T) {
	store, config, _ := createRunningTestInterface(t)
	unlock := store.lockInterfaceOperations(config.ID)
	result := make(chan model.Interface, 1)
	go func() {
		settled, _ := store.GetSettled(config.ID)
		result <- settled
	}()

	select {
	case <-result:
		t.Fatal("settled read returned before the Interface operation completed")
	case <-time.After(30 * time.Millisecond):
	}
	unlock()

	select {
	case settled := <-result:
		if settled.Revision != config.Revision {
			t.Fatalf("settled revision %q, want %q", settled.Revision, config.Revision)
		}
	case <-time.After(time.Second):
		t.Fatal("settled read did not resume after the Interface operation completed")
	}
	store.operationMu.Lock()
	defer store.operationMu.Unlock()
	if len(store.operationLocks) != 0 {
		t.Fatalf("unused Interface operation locks were retained: %d", len(store.operationLocks))
	}
}

type transactionalTunnelController struct {
	running         map[string]bool
	calls           []string
	configPath      string
	downConfigs     [][]byte
	upConfigs       [][]byte
	preflightConfig [][]byte
	preflightError  error
	downError       error
	upErrors        []error
	verifyErrors    []error
	incrementalErr  error
}

func (controller *transactionalTunnelController) IsRunning(
	_ context.Context,
	name string,
) (bool, error) {
	controller.calls = append(controller.calls, "running "+name)
	return controller.running[name], nil
}

func (controller *transactionalTunnelController) Down(
	_ context.Context,
	name string,
) error {
	controller.calls = append(controller.calls, "down "+name)
	if controller.configPath != "" {
		data, err := os.ReadFile(controller.configPath)
		if err != nil {
			return err
		}
		controller.downConfigs = append(controller.downConfigs, append([]byte(nil), data...))
	}
	if controller.downError != nil {
		return controller.downError
	}
	controller.running[name] = false
	return nil
}

func (controller *transactionalTunnelController) Up(
	_ context.Context,
	name string,
) error {
	controller.calls = append(controller.calls, "up "+name)
	if controller.configPath != "" {
		data, err := os.ReadFile(controller.configPath)
		if err != nil {
			return err
		}
		controller.upConfigs = append(controller.upConfigs, append([]byte(nil), data...))
	}
	if len(controller.upErrors) > 0 {
		err := controller.upErrors[0]
		controller.upErrors = controller.upErrors[1:]
		if err != nil {
			return err
		}
	}
	controller.running[name] = true
	return nil
}

func (controller *transactionalTunnelController) Verify(
	_ context.Context,
	name string,
) error {
	controller.calls = append(controller.calls, "verify "+name)
	if len(controller.verifyErrors) == 0 {
		return nil
	}
	err := controller.verifyErrors[0]
	controller.verifyErrors = controller.verifyErrors[1:]
	return err
}

func (controller *transactionalTunnelController) ApplyIncremental(
	_ context.Context,
	name string,
	_ model.Interface,
	_ model.Interface,
) error {
	controller.calls = append(controller.calls, "incremental "+name)
	return controller.incrementalErr
}

func (controller *transactionalTunnelController) ValidateConfiguration(
	_ context.Context,
	name string,
	data []byte,
) error {
	controller.calls = append(controller.calls, "preflight "+name)
	controller.preflightConfig = append(controller.preflightConfig, append([]byte(nil), data...))
	return controller.preflightError
}

func TestRestartRequiredMutationNeedsConfirmation(t *testing.T) {
	store, config, input := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)
	input.DNS = []string{"1.1.1.1"}
	original, err := store.RawConfig(config.ID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.UpdateApplied(
		context.Background(), config.ID, config.Revision, input, tunnels, false,
	)
	if !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("error = %v, want ErrRestartRequired", err)
	}
	after, err := store.RawConfig(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, original) {
		t.Fatal("unconfirmed mutation changed the configuration file")
	}
	if len(tunnels.downConfigs) != 0 || len(tunnels.upConfigs) != 0 {
		t.Fatalf("unconfirmed mutation changed runtime: %#v", tunnels.calls)
	}
}

func TestConfirmedRestartUsesOldFileForDownAndNewFileForUp(t *testing.T) {
	store, config, input := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)
	original, err := store.RawConfig(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	input.DNS = []string{"9.9.9.9"}

	_, err = store.UpdateApplied(
		context.Background(), config.ID, config.Revision, input, tunnels, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels.downConfigs) != 1 || !reflect.DeepEqual(tunnels.downConfigs[0], original) {
		t.Fatalf("Down did not see the old file:\n%s", tunnels.downConfigs[0])
	}
	stored, err := store.RawConfig(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels.preflightConfig) != 1 || !reflect.DeepEqual(tunnels.preflightConfig[0], stored) {
		t.Fatal("preflight did not receive the complete new candidate")
	}
	if len(tunnels.upConfigs) != 1 || !reflect.DeepEqual(tunnels.upConfigs[0], stored) {
		t.Fatalf("Up did not see the new file:\n%s", tunnels.upConfigs[0])
	}
}

func TestRawReplacementUsesTheSameConfirmedRestartTransaction(t *testing.T) {
	store, config, _ := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)
	original, err := store.RawConfig(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacement := cloneInterface(config)
	replacement.DNS = []string{"1.1.1.1"}
	newData, err := Serialize(replacement)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.ImportOverApplied(
		context.Background(), config.ID, config.Revision, newData, tunnels, false,
	); !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("unconfirmed raw replacement returned %v", err)
	}
	if _, err := store.ImportOverApplied(
		context.Background(), config.ID, config.Revision, newData, tunnels, true,
	); err != nil {
		t.Fatal(err)
	}
	if len(tunnels.downConfigs) != 1 || !reflect.DeepEqual(tunnels.downConfigs[0], original) {
		t.Fatal("raw replacement Down did not use the old file")
	}
	if len(tunnels.upConfigs) != 1 || !reflect.DeepEqual(tunnels.upConfigs[0], newData) {
		t.Fatal("raw replacement Up did not use the new file")
	}
}

func TestFailedNewStartRestoresOldFileAndRuntime(t *testing.T) {
	store, config, input := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)
	tunnels.upErrors = []error{errors.New("new start failed"), nil}
	original, err := store.RawConfig(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	input.DNS = []string{"8.8.8.8"}

	_, err = store.UpdateApplied(
		context.Background(), config.ID, config.Revision, input, tunnels, true,
	)
	if !errors.Is(err, ErrTunnelOperation) {
		t.Fatalf("error = %v, want tunnel operation error", err)
	}
	stored, readErr := store.RawConfig(config.ID)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(stored, original) {
		t.Fatalf("old file was not restored:\n%s", stored)
	}
	if !tunnels.running[config.ID] {
		t.Fatal("old runtime was not restored")
	}
	if len(tunnels.upConfigs) != 2 || !reflect.DeepEqual(tunnels.upConfigs[1], original) {
		t.Fatalf("rollback Up did not use the old file: %#v", tunnels.upConfigs)
	}
}

func TestPreflightFailureLeavesOldFileAndRuntimeUntouched(t *testing.T) {
	store, config, input := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)
	tunnels.preflightError = errors.New("candidate rejected")
	original, err := store.RawConfig(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	input.DNS = []string{"8.8.4.4"}

	_, err = store.UpdateApplied(
		context.Background(), config.ID, config.Revision, input, tunnels, true,
	)
	if err == nil || err.Error() != "candidate rejected" {
		t.Fatalf("preflight error = %v", err)
	}
	stored, readErr := store.RawConfig(config.ID)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(stored, original) || !tunnels.running[config.ID] {
		t.Fatal("preflight failure changed the old file or runtime")
	}
	if len(tunnels.downConfigs) != 0 || len(tunnels.upConfigs) != 0 {
		t.Fatalf("preflight failure restarted the Interface: %#v", tunnels.calls)
	}
}

func TestHotMutationRemainsIncremental(t *testing.T) {
	store, config, input := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)
	port := uint16(51821)
	input.ListenPort = &port

	_, err := store.UpdateApplied(
		context.Background(), config.ID, config.Revision, input, tunnels, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels.downConfigs) != 0 || len(tunnels.upConfigs) != 0 {
		t.Fatalf("hot mutation restarted the Interface: %#v", tunnels.calls)
	}
	if !containsCall(tunnels.calls, "incremental wg0") {
		t.Fatalf("hot mutation did not apply incrementally: %#v", tunnels.calls)
	}
}

func TestHotMutationFailureRollsBackFileAndRuntime(t *testing.T) {
	store, config, input := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)
	tunnels.incrementalErr = errors.New("sync failed")
	original, err := store.RawConfig(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(51822)
	input.ListenPort = &port

	_, err = store.UpdateApplied(
		context.Background(), config.ID, config.Revision, input, tunnels, false,
	)
	if !errors.Is(err, ErrTunnelOperation) {
		t.Fatalf("error = %v, want tunnel operation error", err)
	}
	stored, readErr := store.RawConfig(config.ID)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(stored, original) {
		t.Fatal("incremental rollback did not restore the old file")
	}
}

func TestMetadataOnlyMutationDoesNotInspectRuntime(t *testing.T) {
	store, config, input := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)
	input.ClientEndpoint = "vpn.example.com:51820"

	_, err := store.UpdateApplied(
		context.Background(), config.ID, config.Revision, input, tunnels, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels.calls) != 0 {
		t.Fatalf("metadata mutation inspected runtime: %#v", tunnels.calls)
	}
}

func TestStoppedRestartFieldOnlyWritesFile(t *testing.T) {
	store, config, input := createRunningTestInterface(t)
	tunnels := testTunnel(store, false)
	input.DNS = []string{"1.0.0.1"}

	_, err := store.UpdateApplied(
		context.Background(), config.ID, config.Revision, input, tunnels, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels.downConfigs) != 0 || len(tunnels.upConfigs) != 0 {
		t.Fatalf("stopped Interface was started: %#v", tunnels.calls)
	}
}

func TestRestartPreflightsBeforeDown(t *testing.T) {
	store, config, _ := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)

	if _, err := store.RestartApplied(
		context.Background(), config.ID, config.Revision, tunnels,
	); err != nil {
		t.Fatal(err)
	}
	want := []string{"preflight wg0", "running wg0", "down wg0", "running wg0", "up wg0", "verify wg0"}
	if !reflect.DeepEqual(tunnels.calls, want) {
		t.Fatalf("calls = %#v, want %#v", tunnels.calls, want)
	}
}

func TestStopAndDeleteUseCurrentNativeFile(t *testing.T) {
	store, config, _ := createRunningTestInterface(t)
	tunnels := testTunnel(store, true)
	current, err := store.RawConfig(config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StopApplied(
		context.Background(), config.ID, config.Revision, tunnels,
	); err != nil {
		t.Fatal(err)
	}
	if len(tunnels.downConfigs) != 1 || !reflect.DeepEqual(tunnels.downConfigs[0], current) {
		t.Fatal("Stop did not use the current native file")
	}

	tunnels.running[config.ID] = true
	tunnels.calls = nil
	tunnels.downConfigs = nil
	if err := store.DeleteApplied(
		context.Background(), config.ID, config.Revision, tunnels,
	); err != nil {
		t.Fatal(err)
	}
	if len(tunnels.downConfigs) != 1 || !reflect.DeepEqual(tunnels.downConfigs[0], current) {
		t.Fatal("Delete did not use the current native file")
	}
	if _, err := os.Stat(filepath.Join(store.directory, "wg0.conf")); !os.IsNotExist(err) {
		t.Fatalf("configuration still exists: %v", err)
	}
}

func createRunningTestInterface(
	t *testing.T,
) (*Store, model.Interface, model.InterfaceInput) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input := model.InterfaceInput{
		PrivateKey: testPrivateKey(t),
		Address:    []string{"10.54.0.1/24"},
	}
	config, err := store.Create("wg0", input)
	if err != nil {
		t.Fatal(err)
	}
	return store, config, input
}

func testTunnel(store *Store, running bool) *transactionalTunnelController {
	return &transactionalTunnelController{
		running:    map[string]bool{"wg0": running},
		configPath: filepath.Join(store.directory, "wg0.conf"),
	}
}

func containsCall(calls []string, value string) bool {
	for _, call := range calls {
		if call == value {
			return true
		}
	}
	return false
}
