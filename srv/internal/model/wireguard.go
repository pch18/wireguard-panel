package model

// Interface 是一个完整的 wg-quick 配置文件。
// ID 与 Filename 均直接由原生配置文件名推导，不写入其他存储。
type Interface struct {
	ID               string   `json:"id"`
	Filename         string   `json:"filename"`
	Revision         string   `json:"revision"`
	PrivateKey       string   `json:"privateKey"`
	Address          []string `json:"address"`
	ListenPort       *uint16  `json:"listenPort,omitempty"`
	DNS              []string `json:"dns"`
	MTU              *int     `json:"mtu,omitempty"`
	ClientEndpoint   string   `json:"clientEndpoint"`
	ClientAllowedIPs []string `json:"clientAllowedIPs"`
	Peers            []Peer   `json:"peers"`
	ValidationErrors []string `json:"validationErrors"`
	// UnmanagedInterfaceLines preserves legal wg-quick fields that the panel
	// can read but does not own. Structured saves must write these lines back
	// unchanged instead of silently deleting them.
	UnmanagedInterfaceLines []string `json:"-"`
}

// InterfaceInput 是面板创建和更新 Interface 配置时允许写入的字段。
// Interface 的名称不属于配置内容，只由文件名决定。
type InterfaceInput struct {
	PrivateKey       string   `json:"privateKey"`
	Address          []string `json:"address"`
	ListenPort       *uint16  `json:"listenPort"`
	DNS              []string `json:"dns"`
	MTU              *int     `json:"mtu"`
	ClientEndpoint   string   `json:"clientEndpoint"`
	ClientAllowedIPs []string `json:"clientAllowedIPs"`
}

// InterfaceCreateInput 将一次性的文件名与 Interface 配置分开。
type InterfaceCreateInput struct {
	Name string `json:"name"`
	InterfaceInput
}

// Peer 包含 wg(8) 配置文件支持的全部 Peer 字段。
// Name 与 PrivateKey 以注释形式写在所属 [Peer] 段中，
// 保持原生 WireGuard 配置兼容性。
type Peer struct {
	Name                string   `json:"name"`
	PrivateKey          string   `json:"privateKey"`
	PublicKey           string   `json:"publicKey"`
	PresharedKey        string   `json:"presharedKey"`
	AllowedIPs          []string `json:"allowedIPs"`
	Endpoint            string   `json:"endpoint"`
	PersistentKeepalive *uint16  `json:"persistentKeepalive,omitempty"`
}

type PeerInput struct {
	Name                string   `json:"name"`
	PrivateKey          string   `json:"privateKey"`
	PublicKey           string   `json:"publicKey"`
	PresharedKey        string   `json:"presharedKey"`
	AllowedIPs          []string `json:"allowedIPs"`
	Endpoint            string   `json:"endpoint"`
	PersistentKeepalive *uint16  `json:"persistentKeepalive"`
}

type IPPlan struct {
	Revision          string          `json:"revision"`
	Networks          []IPNetworkPlan `json:"networks"`
	AllowedRanges     []string        `json:"allowedRanges"`
	ReservedAddresses []string        `json:"reservedAddresses"`
	Assignments       []IPAssignment  `json:"assignments"`
	Conflicts         []IPConflict    `json:"conflicts"`
}

type IPAssignment struct {
	AllowedIP     string `json:"allowedIP"`
	PeerPublicKey string `json:"peerPublicKey"`
	PeerName      string `json:"peerName"`
}

type IPNetworkPlan struct {
	Network              string   `json:"network"`
	InterfaceAddresses   []string `json:"interfaceAddresses"`
	AllocatedAddresses   []string `json:"allocatedAddresses"`
	SuggestedAddress     string   `json:"suggestedAddress"`
	SuggestedAllowedIP   string   `json:"suggestedAllowedIP"`
	AvailableForPlanning bool     `json:"availableForPlanning"`
}

type IPConflict struct {
	Kind          string `json:"kind"`
	Address       string `json:"address"`
	PeerPublicKey string `json:"peerPublicKey,omitempty"`
	Message       string `json:"message"`
}
