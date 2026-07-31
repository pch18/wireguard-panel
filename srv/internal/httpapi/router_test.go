package httpapi

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"wireguard-panel/internal/model"
	"wireguard-panel/internal/service"
	"wireguard-panel/internal/wgconfig"

	"github.com/gin-gonic/gin"
)

func testRouter(t *testing.T) *gin.Engine {
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
		WebFiles: fs.FS(webFiles),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
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
	_, peerKey := testWireGuardKeyPair(t)
	input := model.InterfaceInput{
		Name:       "Tokyo gateway",
		PrivateKey: key,
		Address:    []string{"10.20.0.1/24", "fd20::1/64"},
		ListenPort: uint16Pointer(51820),
		DNS:        []string{"1.1.1.1"},
		MTU:        intPointer(1420),
		Table:      "auto",
		PostUp:     []string{"iptables -A FORWARD -i %i -j ACCEPT"},
		SaveConfig: true,
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
	if config.ID != 0 || config.Filename != "wg0.conf" || config.Name != input.Name {
		t.Fatalf("unexpected created interface: %#v", config)
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
		"/api/v1/interfaces/0/peers",
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
	if peer.ID == "" || peer.PublicKey != peerKey {
		t.Fatalf("unexpected peer: %#v", peer)
	}

	fetched := performJSON(t, router, http.MethodGet, "/api/v1/interfaces/0", nil, cookie)
	if fetched.Code != http.StatusOK {
		t.Fatalf("get returned %d: %s", fetched.Code, fetched.Body.String())
	}
	if err := json.Unmarshal(fetched.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Peers) != 1 || config.Peers[0].ID != peer.ID {
		t.Fatalf("peer was not persisted: %#v", config.Peers)
	}

	deletedPeer := performJSONWithRevision(
		t,
		router,
		http.MethodDelete,
		"/api/v1/interfaces/0/peers/"+peer.ID,
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
		"/api/v1/interfaces/0",
		nil,
		cookie,
		config.Revision,
	)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete interface returned %d: %s", deleted.Code, deleted.Body.String())
	}
}

func TestWireGuardAtomicRevisionGeneratedPeerAndClientDownload(t *testing.T) {
	router := testRouter(t)
	cookie := loginCookie(t, router)
	created := performJSON(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces",
		model.InterfaceInput{
			Name:             "Client gateway",
			PrivateKey:       testWireGuardPrivateKey(t),
			Address:          []string{"10.80.0.1/24"},
			ClientEndpoint:   "vpn.example.com:51820",
			ClientDNS:        []string{"1.1.1.1"},
			ClientAllowedIPs: []string{"10.80.0.0/24"},
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

	createdPeer := performJSONWithRevision(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/0/peers",
		model.PeerInput{
			Name:            "Generated client",
			GenerateKeyPair: true,
			ClientAddress:   []string{"10.80.0.2/24"},
			AllowedIPs:      []string{"10.80.0.2/32"},
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
		config.Peers[0].PrivateKey == "" {
		t.Fatalf("generated peer response is incomplete: %#v", config)
	}

	stale := performJSONWithRevision(
		t,
		router,
		http.MethodPost,
		"/api/v1/interfaces/0/peers",
		model.PeerInput{
			Name:            "Stale client",
			GenerateKeyPair: true,
			ClientAddress:   []string{"10.80.0.3/24"},
			AllowedIPs:      []string{"10.80.0.3/32"},
		},
		cookie,
		originalRevision,
	)
	if stale.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale write returned %d: %s", stale.Code, stale.Body.String())
	}

	missingRevision := performJSON(
		t,
		router,
		http.MethodDelete,
		"/api/v1/interfaces/0/peers/"+config.Peers[0].ID,
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

	download := performJSON(
		t,
		router,
		http.MethodGet,
		"/api/v1/interfaces/0/peers/"+config.Peers[0].ID+"/client-config",
		nil,
		cookie,
	)
	if download.Code != http.StatusOK ||
		!bytes.Contains(download.Body.Bytes(), []byte("[Interface]")) ||
		!bytes.Contains(download.Body.Bytes(), []byte("[Peer]")) {
		t.Fatalf("client config returned %d: %s", download.Code, download.Body.String())
	}
	if disposition := download.Header().Get("Content-Disposition"); disposition == "" {
		t.Fatal("client config response is missing Content-Disposition")
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
