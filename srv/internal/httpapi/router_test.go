package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"wireguard-panel/internal/model"
	"wireguard-panel/internal/mtuprobe"
	"wireguard-panel/internal/service"
	"wireguard-panel/internal/wgconfig"
	"wireguard-panel/internal/wgstatus"

	"github.com/gin-gonic/gin"
)

type stubMTUDetector struct {
	result mtuprobe.Result
	err    error
}

type staticDumpRunner struct {
	output []byte
}

func (runner *staticDumpRunner) Dump(context.Context) ([]byte, error) {
	return runner.output, nil
}

type stubTunnelController struct{}

type runningTunnelController struct {
	running bool
	down    int
	up      int
}

func (stubTunnelController) IsRunning(context.Context, string) (bool, error) {
	return false, nil
}

func (stubTunnelController) Down(context.Context, string) error   { return nil }
func (stubTunnelController) Up(context.Context, string) error     { return nil }
func (stubTunnelController) Verify(context.Context, string) error { return nil }

func (controller *runningTunnelController) IsRunning(context.Context, string) (bool, error) {
	return controller.running, nil
}

func (controller *runningTunnelController) Down(context.Context, string) error {
	controller.down++
	controller.running = false
	return nil
}

func (controller *runningTunnelController) Up(context.Context, string) error {
	controller.up++
	controller.running = true
	return nil
}

func (*runningTunnelController) Verify(context.Context, string) error { return nil }

func (detector stubMTUDetector) Detect(context.Context) (mtuprobe.Result, error) {
	return detector.result, detector.err
}

func testRouter(t *testing.T) *gin.Engine {
	return testRouterWithMTUProbe(t, stubMTUDetector{result: mtuprobe.Result{
		Target:        mtuprobe.DefaultTarget,
		Method:        "icmp-echo-df",
		PathMTU:       1500,
		WireGuardMTU:  1420,
		OverheadBytes: 80,
	}})
}

func testRouterWithMTUProbe(t *testing.T, probe mtuprobe.Detector) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	auth, err := service.NewAuthService("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	configs, err := wgconfig.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	webFiles := fstest.MapFS{
		"web/index.html": &fstest.MapFile{Data: []byte("<main>app shell</main>")},
	}
	router, err := NewRouter(Dependencies{
		Auth:     auth,
		Configs:  configs,
		MTUProbe: probe,
		Tunnels:  stubTunnelController{},
		WebFiles: fs.FS(webFiles),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func TestMTUProbeRequiresSessionAndReturnsSuggestedWireGuardMTU(t *testing.T) {
	router := testRouter(t)
	unauthorized := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/wireguard/mtu-probe",
		nil,
		nil,
	)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized probe returned %d", unauthorized.Code)
	}
	response := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/wireguard/mtu-probe",
		nil,
		loginCookie(t, router),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("probe returned %d: %s", response.Code, response.Body.String())
	}
	var result mtuprobe.Result
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Target != mtuprobe.DefaultTarget || result.PathMTU != 1500 ||
		result.WireGuardMTU != 1420 || result.OverheadBytes != 80 {
		t.Fatalf("unexpected probe result: %#v", result)
	}
}

func TestRestartRequiredWriteNeedsExplicitConfirmationHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth, err := service.NewAuthService("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	configs, err := wgconfig.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.91.0.1/24\n", testWireGuardPrivateKey(t))
	if err := os.WriteFile(filepath.Join(directory, "wg0.conf"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := configs.Get("wg0")
	if err != nil {
		t.Fatal(err)
	}
	tunnels := &runningTunnelController{running: true}
	webFiles := fstest.MapFS{
		"web/index.html": &fstest.MapFile{Data: []byte("<main>app shell</main>")},
	}
	router, err := NewRouter(Dependencies{
		Auth: auth, Configs: configs, Tunnels: tunnels, WebFiles: fs.FS(webFiles),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := loginCookie(t, router)
	input := model.InterfaceInput{
		PrivateKey: config.PrivateKey,
		Address:    config.Address,
		DNS:        []string{"1.1.1.1"},
	}

	unconfirmed := performJSONWithRevision(
		t, router, http.MethodPut, "/api/v1/interfaces/wg0", input, cookie, config.Revision,
	)
	if unconfirmed.Code != http.StatusConflict ||
		!strings.Contains(unconfirmed.Body.String(), `"code":"restart_required"`) {
		t.Fatalf("unconfirmed restart returned %d: %s", unconfirmed.Code, unconfirmed.Body.String())
	}
	if tunnels.down != 0 || tunnels.up != 0 {
		t.Fatalf("unconfirmed request changed runtime: down=%d up=%d", tunnels.down, tunnels.up)
	}

	confirmed := performJSONWithRevision(
		t, router, http.MethodPut, "/api/v1/interfaces/wg0", input, cookie, config.Revision, true,
	)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirmed restart returned %d: %s", confirmed.Code, confirmed.Body.String())
	}
	if tunnels.down != 1 || tunnels.up != 1 || !tunnels.running {
		t.Fatalf("confirmed request did not restart once: %#v", tunnels)
	}
}

func TestRuntimeStatusConfirmsRunningStateWithoutTrafficSample(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth, err := service.NewAuthService("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	configs, err := wgconfig.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf("[Interface]\nPrivateKey = %s\n", testWireGuardPrivateKey(t))
	if err := os.WriteFile(filepath.Join(directory, "wg0.conf"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	webFiles := fstest.MapFS{
		"web/index.html": &fstest.MapFile{Data: []byte("<main>app shell</main>")},
	}
	router, err := NewRouter(Dependencies{
		Auth: auth, Configs: configs, Tunnels: &runningTunnelController{running: true},
		WebFiles: fs.FS(webFiles),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := performJSON(
		t,
		router,
		http.MethodGet,
		"/api/v1/interfaces/wg0/status",
		nil,
		loginCookie(t, router),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status returned %d: %s", response.Code, response.Body.String())
	}
	var status model.InterfaceRuntimeStatus
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.RuntimeStateAvailable || !status.Running {
		t.Fatalf("running state was not confirmed: %#v", status)
	}
	if status.CollectorAvailable {
		t.Fatalf("missing traffic sample was reported as available: %#v", status)
	}
}

func TestInterfaceTrafficSSEStreamsHistoryAndBackgroundUpdates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth, err := service.NewAuthService("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	configs, err := wgconfig.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := &staticDumpRunner{
		output: []byte("Traffic\tprivate\tpublic\t51820\toff\n"),
	}
	collector := wgstatus.NewCollector(runner, 3*time.Minute)
	webFiles := fstest.MapFS{
		"web/index.html": &fstest.MapFile{Data: []byte("<main>app shell</main>")},
	}
	applicationContext, stopApplication := context.WithCancel(context.Background())
	defer stopApplication()
	router, err := NewRouter(Dependencies{
		Auth:               auth,
		Configs:            configs,
		Status:             collector,
		MTUProbe:           stubMTUDetector{},
		Tunnels:            stubTunnelController{},
		WebFiles:           fs.FS(webFiles),
		ApplicationContext: applicationContext,
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := loginCookie(t, router)
	created := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces",
		model.InterfaceCreateInput{
			Name: "Traffic",
			InterfaceInput: model.InterfaceInput{
				PrivateKey: testWireGuardPrivateKey(t),
				Address:    []string{"10.90.0.1/24"},
			},
		},
		cookie,
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	var config model.Interface
	if err := json.Unmarshal(created.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	_, peerPublicKey := testWireGuardKeyPair(t)
	createdPeer := performJSONWithRevision(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/Traffic/peers",
		model.PeerInput{
			Name:       "Traffic Peer",
			PublicKey:  peerPublicKey,
			AllowedIPs: []string{"10.90.0.2/32"},
		},
		cookie,
		config.Revision,
	)
	if createdPeer.Code != http.StatusCreated {
		t.Fatalf("create Peer returned %d: %s", createdPeer.Code, createdPeer.Body.String())
	}
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	runner.output = []byte(fmt.Sprintf(
		"Traffic\tprivate\tpublic\t51820\toff\n"+
			"Traffic\t%s\t(none)\t198.51.100.20:51820\t10.90.0.2/32\t0\t1000\t2000\t0\n",
		peerPublicKey,
	))
	if err := collector.Sample(context.Background(), start); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(router)
	defer server.Close()
	requestContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodGet,
		server.URL+"/api/v1/interfaces/Traffic/events",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(cookie)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		!strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") ||
		response.Header.Get("Content-Encoding") != "" {
		t.Fatalf("unexpected SSE response: status=%d headers=%v", response.StatusCode, response.Header)
	}

	scanner := bufio.NewScanner(response.Body)
	history := readTrafficEvent(t, scanner)
	if history.Kind != "history" ||
		len(history.InterfaceTraffic) != 1 ||
		len(history.Status.Peers) != 1 ||
		len(history.PeerTraffic[peerPublicKey]) != 1 {
		t.Fatalf("unexpected initial traffic event: %#v", history)
	}
	runner.output = []byte(fmt.Sprintf(
		"Traffic\tprivate\tpublic\t51820\toff\n"+
			"Traffic\t%s\t(none)\t198.51.100.20:51820\t10.90.0.2/32\t0\t1600\t2600\t0\n",
		peerPublicKey,
	))
	if err := collector.Sample(context.Background(), start.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	update := readTrafficEvent(t, scanner)
	if update.Kind != "update" ||
		len(update.InterfaceTraffic) != 1 ||
		len(update.PeerTraffic[peerPublicKey]) != 1 ||
		update.Status.Peers[0].ReceiveBytesPerSecond != 200 ||
		update.Status.Peers[0].SendBytesPerSecond != 200 {
		t.Fatalf("unexpected traffic update: %#v", update)
	}

	stopApplication()
	streamEnded := make(chan error, 1)
	go func() {
		for scanner.Scan() {
		}
		streamEnded <- scanner.Err()
	}()
	select {
	case err := <-streamEnded:
		if err != nil {
			t.Fatalf("SSE stream ended with an error during application shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSE stream did not close during application shutdown")
	}
}

func readTrafficEvent(
	t *testing.T,
	scanner *bufio.Scanner,
) model.InterfaceTrafficEvent {
	t.Helper()
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var event model.InterfaceTrafficEvent
		if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &event); err != nil {
			t.Fatal(err)
		}
		return event
	}
	t.Fatalf("SSE stream ended before a traffic event: %v", scanner.Err())
	return model.InterfaceTrafficEvent{}
}

func TestWireGuardInventoryReportsInvalidFilesWithoutFailingScan(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(directory, "wg0.conf"),
		[]byte("not a WireGuard configuration"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	configs, err := wgconfig.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	(&wireGuardHandler{configs: configs}).list(context)
	if recorder.Code != http.StatusOK {
		t.Fatalf("inventory returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var inventory struct {
		Interfaces    []model.Interface           `json:"interfaces"`
		OccupiedNames []string                    `json:"occupiedNames"`
		Problems      []wgconfig.InterfaceProblem `json:"problems"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Interfaces) != 0 {
		t.Fatalf("unexpected parsed Interfaces: %#v", inventory.Interfaces)
	}
	if len(inventory.OccupiedNames) != 1 || inventory.OccupiedNames[0] != "wg0" {
		t.Fatalf("unexpected occupied names: %#v", inventory.OccupiedNames)
	}
	if len(inventory.Problems) != 1 || inventory.Problems[0].ID != "wg0" {
		t.Fatalf("unexpected inventory problems: %#v", inventory.Problems)
	}
}

func performJSON(
	t *testing.T,
	router http.Handler,
	method string,
	path string,
	body any,
	cookie *http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&requestBody).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, &requestBody)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func performJSONWithRevision(
	t *testing.T,
	router http.Handler,
	method string,
	path string,
	body any,
	cookie *http.Cookie,
	revision string,
	restartConfirmed ...bool,
) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&requestBody).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, &requestBody)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("If-Match", `"`+revision+`"`)
	if len(restartConfirmed) > 0 && restartConfirmed[0] {
		request.Header.Set("X-WireGuard-Restart-Confirmed", "true")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func loginCookie(t *testing.T, router http.Handler) *http.Cookie {
	t.Helper()
	response := performJSON(t, router, http.MethodPost, "/api/v1/login", map[string]string{
		"username": "admin",
		"password": "admin",
	}, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie lacks security attributes: %#v", cookies[0])
	}
	return cookies[0]
}

func TestEnvironmentAuthenticationSessionAndLogout(t *testing.T) {
	router := testRouter(t)
	badLogin := performJSON(t, router, http.MethodPost, "/api/v1/login", map[string]string{
		"username": "admin",
		"password": "wrong",
	}, nil)
	if badLogin.Code != http.StatusUnauthorized {
		t.Fatalf("invalid login returned %d", badLogin.Code)
	}

	cookie := loginCookie(t, router)
	session := performJSON(t, router, http.MethodGet, "/api/v1/session", nil, cookie)
	if session.Code != http.StatusOK {
		t.Fatalf("session returned %d: %s", session.Code, session.Body.String())
	}
	loggedOut := performJSON(t, router, http.MethodPost, "/api/v1/logout", nil, cookie)
	if loggedOut.Code != http.StatusNoContent {
		t.Fatalf("logout returned %d", loggedOut.Code)
	}
	expired := performJSON(t, router, http.MethodGet, "/api/v1/session", nil, cookie)
	if expired.Code != http.StatusUnauthorized {
		t.Fatalf("logged out session returned %d", expired.Code)
	}
}

func TestWireGuardKeyGenerationEndpointIsNotExposed(t *testing.T) {
	router := testRouter(t)
	cookie := loginCookie(t, router)
	response := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/wireguard/key-pair",
		map[string]string{},
		cookie,
	)
	if response.Code != http.StatusNotFound {
		t.Fatalf("removed key endpoint returned %d: %s", response.Code, response.Body.String())
	}
}

func TestAuthenticatedPasswordChange(t *testing.T) {
	router := testRouter(t)
	currentCookie := loginCookie(t, router)
	otherCookie := loginCookie(t, router)

	wrongCurrent := performJSON(
		t,
		router,
		http.MethodPut,
		"/api/v1/account/password",
		map[string]string{
			"currentPassword": "wrong",
			"newPassword":     "NewPassword888",
		},
		currentCookie,
	)
	if wrongCurrent.Code != http.StatusForbidden {
		t.Fatalf("wrong current password returned %d: %s", wrongCurrent.Code, wrongCurrent.Body.String())
	}

	changed := performJSON(
		t,
		router,
		http.MethodPut,
		"/api/v1/account/password",
		map[string]string{
			"currentPassword": "admin",
			"newPassword":     "NewPassword888",
		},
		currentCookie,
	)
	if changed.Code != http.StatusNoContent {
		t.Fatalf("password change returned %d: %s", changed.Code, changed.Body.String())
	}
	currentSession := performJSON(
		t,
		router,
		http.MethodGet,
		"/api/v1/session",
		nil,
		currentCookie,
	)
	if currentSession.Code != http.StatusOK {
		t.Fatalf("current session returned %d after password change", currentSession.Code)
	}
	otherSession := performJSON(
		t,
		router,
		http.MethodGet,
		"/api/v1/session",
		nil,
		otherCookie,
	)
	if otherSession.Code != http.StatusUnauthorized {
		t.Fatalf("other session returned %d after password change", otherSession.Code)
	}
	oldLogin := performJSON(t, router, http.MethodPost, "/api/v1/login", map[string]string{
		"username": "admin",
		"password": "admin",
	}, nil)
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("old password login returned %d", oldLogin.Code)
	}
	newLogin := performJSON(t, router, http.MethodPost, "/api/v1/login", map[string]string{
		"username": "admin",
		"password": "NewPassword888",
	}, nil)
	if newLogin.Code != http.StatusOK {
		t.Fatalf("new password login returned %d: %s", newLogin.Code, newLogin.Body.String())
	}
}

func TestSPAFallbackAndUnknownAPI(t *testing.T) {
	router := testRouter(t)
	page := performJSON(t, router, http.MethodGet, "/any/page", nil, nil)
	if page.Code != http.StatusOK || !bytes.Contains(page.Body.Bytes(), []byte("app shell")) {
		t.Fatalf("SPA fallback returned %d: %s", page.Code, page.Body.String())
	}
	unknown := performJSON(t, router, http.MethodGet, "/api/v1/missing", nil, nil)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown API returned %d", unknown.Code)
	}
}

func TestWireGuardCRUDRequiresSessionAndPersistsNativeConfiguration(t *testing.T) {
	router := testRouter(t)
	key, _ := testWireGuardKeyPair(t)
	peerKey := "//////////////////////////////////////////8="
	input := model.InterfaceCreateInput{
		Name: "Tokyo_gateway",
		InterfaceInput: model.InterfaceInput{
			PrivateKey: key,
			Address:    []string{"10.20.0.1/24", "fd20::1/64"},
			ListenPort: uint16Pointer(51820),
			DNS:        []string{"1.1.1.1"},
			MTU:        intPointer(1420),
		},
	}

	unauthorized := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces",
		input,
		nil,
	)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized create returned %d", unauthorized.Code)
	}

	cookie := loginCookie(t, router)
	created := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces",
		input,
		cookie,
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	var config model.Interface
	if err := json.Unmarshal(created.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if config.ID != "Tokyo_gateway" || config.Filename != "Tokyo_gateway.conf" {
		t.Fatalf("unexpected created interface: %#v", config)
	}
	inventoryResponse := performJSON(
		t,
		router,
		http.MethodGet,
		"/api/v1/interfaces",
		nil,
		cookie,
	)
	if inventoryResponse.Code != http.StatusOK {
		t.Fatalf("Interface inventory returned %d: %s", inventoryResponse.Code, inventoryResponse.Body.String())
	}
	var inventory struct {
		Interfaces    []model.Interface           `json:"interfaces"`
		OccupiedNames []string                    `json:"occupiedNames"`
		Problems      []wgconfig.InterfaceProblem `json:"problems"`
	}
	if err := json.Unmarshal(inventoryResponse.Body.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Interfaces) != 1 || inventory.Interfaces[0].ID != "Tokyo_gateway" {
		t.Fatalf("unexpected inventory Interfaces: %#v", inventory.Interfaces)
	}
	if len(inventory.OccupiedNames) != 1 || inventory.OccupiedNames[0] != "Tokyo_gateway" {
		t.Fatalf("unexpected occupied names: %#v", inventory.OccupiedNames)
	}
	if len(inventory.Problems) != 0 {
		t.Fatalf("unexpected inventory problems: %#v", inventory.Problems)
	}

	peerInput := model.PeerInput{
		PublicKey:           peerKey,
		AllowedIPs:          []string{"10.20.0.2/32"},
		Endpoint:            "peer.example.com:51820",
		PersistentKeepalive: uint16Pointer(25),
	}
	createdPeer := performJSONWithRevision(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/Tokyo_gateway/peers",
		peerInput,
		cookie,
		config.Revision,
	)
	if createdPeer.Code != http.StatusCreated {
		t.Fatalf("create peer returned %d: %s", createdPeer.Code, createdPeer.Body.String())
	}
	if err := json.Unmarshal(createdPeer.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Peers) != 1 {
		t.Fatalf("unexpected peer response: %#v", config)
	}
	peer := config.Peers[0]
	if peer.PublicKey != peerKey {
		t.Fatalf("unexpected peer: %#v", peer)
	}

	fetched := performJSON(t, router, http.MethodGet, "/api/v1/interfaces/Tokyo_gateway", nil, cookie)
	if fetched.Code != http.StatusOK {
		t.Fatalf("get returned %d: %s", fetched.Code, fetched.Body.String())
	}
	if err := json.Unmarshal(fetched.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Peers) != 1 || config.Peers[0].PublicKey != peer.PublicKey {
		t.Fatalf("peer was not persisted: %#v", config.Peers)
	}
	_, replacementKey := testWireGuardKeyPair(t)
	peerInput.PublicKey = replacementKey
	peerInput.AllowedIPs = []string{"10.20.0.3/32"}
	updatedPeer := performJSONWithRevision(
		t,
		router,
		http.MethodPut,
		"/api/v1/interfaces/Tokyo_gateway/peers/"+peerPath(t, peer.PublicKey),
		peerInput,
		cookie,
		config.Revision,
	)
	if updatedPeer.Code != http.StatusOK {
		t.Fatalf("update peer returned %d: %s", updatedPeer.Code, updatedPeer.Body.String())
	}
	if err := json.Unmarshal(updatedPeer.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Peers) != 1 || config.Peers[0].PublicKey != replacementKey {
		t.Fatalf("peer was not located by its original PublicKey: %#v", config.Peers)
	}

	deletedPeer := performJSONWithRevision(
		t,
		router,
		http.MethodDelete,
		"/api/v1/interfaces/Tokyo_gateway/peers/"+peerPath(t, replacementKey),
		nil,
		cookie,
		config.Revision,
	)
	if deletedPeer.Code != http.StatusOK {
		t.Fatalf("delete peer returned %d: %s", deletedPeer.Code, deletedPeer.Body.String())
	}
	if err := json.Unmarshal(deletedPeer.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	deleted := performJSONWithRevision(
		t,
		router,
		http.MethodDelete,
		"/api/v1/interfaces/Tokyo_gateway",
		nil,
		cookie,
		config.Revision,
	)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete interface returned %d: %s", deleted.Code, deleted.Body.String())
	}
}

func TestWireGuardRenameUsesDedicatedRevisionProtectedEndpoint(t *testing.T) {
	router := testRouter(t)
	cookie := loginCookie(t, router)
	created := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces",
		model.InterfaceCreateInput{
			Name: "Tokyo",
			InterfaceInput: model.InterfaceInput{
				PrivateKey: testWireGuardPrivateKey(t),
				Address:    []string{"10.81.0.1/24"},
			},
		},
		cookie,
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	if bytes.Contains(created.Body.Bytes(), []byte(`"name"`)) {
		t.Fatalf("Interface response still exposes a Name field: %s", created.Body.String())
	}
	var config model.Interface
	if err := json.Unmarshal(created.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}

	missingRevision := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/Tokyo/rename",
		map[string]string{"name": "Osaka"},
		cookie,
	)
	if missingRevision.Code != http.StatusPreconditionRequired {
		t.Fatalf("rename without revision returned %d", missingRevision.Code)
	}

	renamed := performJSONWithRevision(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/Tokyo/rename",
		map[string]string{"name": "Osaka_2"},
		cookie,
		config.Revision,
	)
	if renamed.Code != http.StatusOK {
		t.Fatalf("rename returned %d: %s", renamed.Code, renamed.Body.String())
	}
	if err := json.Unmarshal(renamed.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if config.ID != "Osaka_2" || config.Filename != "Osaka_2.conf" {
		t.Fatalf("unexpected rename response: %#v", config)
	}
	oldConfig := performJSON(
		t,
		router,
		http.MethodGet,
		"/api/v1/interfaces/Tokyo",
		nil,
		cookie,
	)
	if oldConfig.Code != http.StatusNotFound {
		t.Fatalf("old Interface returned %d after rename", oldConfig.Code)
	}
}

func TestWireGuardAtomicRevisionGeneratedPeerAndClientPreview(t *testing.T) {
	router := testRouter(t)
	cookie := loginCookie(t, router)
	created := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces",
		model.InterfaceCreateInput{
			Name: "Client_gateway",
			InterfaceInput: model.InterfaceInput{
				PrivateKey:       testWireGuardPrivateKey(t),
				Address:          []string{"10.80.0.1/24"},
				ClientEndpoint:   "vpn.example.com:51820",
				ClientAllowedIPs: []string{"10.80.0.0/24"},
			},
		},
		cookie,
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	var config model.Interface
	if err := json.Unmarshal(created.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	originalRevision := config.Revision
	peerPrivateKey, peerPublicKey := testWireGuardKeyPair(t)

	createdPeer := performJSONWithRevision(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/Client_gateway/peers",
		model.PeerInput{
			Name:       "Browser generated client",
			PrivateKey: peerPrivateKey,
			PublicKey:  peerPublicKey,
			AllowedIPs: []string{"10.80.0.2/32"},
		},
		cookie,
		originalRevision,
	)
	if createdPeer.Code != http.StatusCreated {
		t.Fatalf("create peer returned %d: %s", createdPeer.Code, createdPeer.Body.String())
	}
	if err := json.Unmarshal(createdPeer.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if config.Revision == originalRevision ||
		len(config.Peers) != 1 ||
		config.Peers[0].PrivateKey != peerPrivateKey {
		t.Fatalf("browser-generated peer response is incomplete: %#v", config)
	}
	_, stalePublicKey := testWireGuardKeyPair(t)

	stale := performJSONWithRevision(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/Client_gateway/peers",
		model.PeerInput{
			Name:       "Stale client",
			PublicKey:  stalePublicKey,
			AllowedIPs: []string{"10.80.0.3/32"},
		},
		cookie,
		originalRevision,
	)
	if stale.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale write returned %d: %s", stale.Code, stale.Body.String())
	}
	invalidPath := performJSON(
		t,
		router,
		http.MethodDelete,
		"/api/v1/interfaces/Client_gateway/peers/not-a-public-key",
		nil,
		cookie,
	)
	if invalidPath.Code != http.StatusBadRequest {
		t.Fatalf("invalid Peer path returned %d: %s", invalidPath.Code, invalidPath.Body.String())
	}

	missingRevision := performJSON(
		t,
		router,
		http.MethodDelete,
		"/api/v1/interfaces/Client_gateway/peers/"+peerPath(t, config.Peers[0].PublicKey),
		nil,
		cookie,
	)
	if missingRevision.Code != http.StatusPreconditionRequired {
		t.Fatalf(
			"missing revision returned %d: %s",
			missingRevision.Code,
			missingRevision.Body.String(),
		)
	}

	preview := performJSON(
		t,
		router,
		http.MethodGet,
		"/api/v1/interfaces/Client_gateway/peers/"+peerPath(t, config.Peers[0].PublicKey)+"/client-config",
		nil,
		cookie,
	)
	if preview.Code != http.StatusOK ||
		!bytes.Contains(preview.Body.Bytes(), []byte("[Interface]")) ||
		!bytes.Contains(preview.Body.Bytes(), []byte("[Peer]")) {
		t.Fatalf("client config returned %d: %s", preview.Code, preview.Body.String())
	}
	if disposition := preview.Header().Get("Content-Disposition"); disposition != "" {
		t.Fatalf("client preview must not trigger a download: %q", disposition)
	}
}

func TestWireGuardTextConfigurationImportAndExport(t *testing.T) {
	router := testRouter(t)
	cookie := loginCookie(t, router)
	interfaceSource := fmt.Sprintf(`# Name = Imported API gateway
[Interface]
PrivateKey = %s
Address = 10.93.0.1/24
`, testWireGuardPrivateKey(t))
	created := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/import",
		map[string]string{"config": interfaceSource},
		cookie,
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("Interface import returned %d: %s", created.Code, created.Body.String())
	}
	var config model.Interface
	if err := json.Unmarshal(created.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	exported := performJSON(
		t,
		router,
		http.MethodGet,
		"/api/v1/interfaces/wg0/config",
		nil,
		cookie,
	)
	if exported.Code != http.StatusOK ||
		bytes.Contains(exported.Body.Bytes(), []byte("# Name = Imported API gateway")) ||
		exported.Header().Get("Content-Disposition") != "" {
		t.Fatalf("Interface export returned %d: %s", exported.Code, exported.Body.String())
	}

	_, peerPublicKey := testWireGuardKeyPair(t)
	_, secondPeerPublicKey := testWireGuardKeyPair(t)
	peerSource := fmt.Sprintf(`# Name = API peer
[Peer]
PublicKey = %s
AllowedIPs = 10.93.0.2/32

# Name = API peer 2
[Peer]
PublicKey = %s
AllowedIPs = 10.93.0.3/32
`, peerPublicKey, secondPeerPublicKey)
	peerImported := performJSONWithRevision(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/wg0/peers/import",
		map[string]string{"config": peerSource},
		cookie,
		config.Revision,
	)
	if peerImported.Code != http.StatusCreated {
		t.Fatalf("Peer import returned %d: %s", peerImported.Code, peerImported.Body.String())
	}
	if err := json.Unmarshal(peerImported.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Peers) != 2 ||
		config.Peers[0].Name != "API peer" ||
		config.Peers[1].Name != "API peer 2" {
		t.Fatalf("unexpected imported Peers: %#v", config.Peers)
	}
	peerExported := performJSON(
		t,
		router,
		http.MethodGet,
		"/api/v1/interfaces/wg0/peers/"+peerPath(t, config.Peers[0].PublicKey)+"/config",
		nil,
		cookie,
	)
	if peerExported.Code != http.StatusOK ||
		!bytes.Contains(peerExported.Body.Bytes(), []byte("# Name = API peer")) ||
		!bytes.Contains(peerExported.Body.Bytes(), []byte("[Peer]")) {
		t.Fatalf("Peer export returned %d: %s", peerExported.Code, peerExported.Body.String())
	}

	invalid := performJSONWithRevision(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/wg0/peers/import",
		map[string]string{"config": "[Peer]\nMadeUp = value\n"},
		cookie,
		config.Revision,
	)
	if invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid Peer import returned %d: %s", invalid.Code, invalid.Body.String())
	}
}

func uint16Pointer(value uint16) *uint16 {
	return &value
}

func intPointer(value int) *int {
	return &value
}

func testWireGuardKeyPair(t *testing.T) (string, string) {
	t.Helper()
	privateKey, publicKey, err := wgconfig.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, publicKey
}

func testWireGuardPrivateKey(t *testing.T) string {
	t.Helper()
	privateKey, _ := testWireGuardKeyPair(t)
	return privateKey
}

func peerPath(t *testing.T, publicKey string) string {
	t.Helper()
	path, err := wgconfig.EncodePeerPublicKeyPath(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return path
}
