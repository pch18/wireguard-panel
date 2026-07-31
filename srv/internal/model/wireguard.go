package model

// Interface 是一个完整的 wg-quick 配置文件。
// ID 与 Filename 均由文件名 wg<ID>.conf 推导，不写入其他存储。
type Interface struct {
	ID                        int      `json:"id"`
	Filename                  string   `json:"filename"`
	Revision                  string   `json:"revision"`
	Name                      string   `json:"name"`
	PrivateKey                string   `json:"privateKey"`
	Address                   []string `json:"address"`
	ListenPort                *uint16  `json:"listenPort,omitempty"`
	FwMark                    string   `json:"fwMark"`
	DNS                       []string `json:"dns"`
	MTU                       *int     `json:"mtu,omitempty"`
	Table                     string   `json:"table"`
	PreUp                     []string `json:"preUp"`
	PostUp                    []string `json:"postUp"`
	PreDown                   []string `json:"preDown"`
	PostDown                  []string `json:"postDown"`
	SaveConfig                bool     `json:"saveConfig"`
	ClientEndpoint            string   `json:"clientEndpoint"`
	ClientDNS                 []string `json:"clientDNS"`
	ClientAllowedIPs          []string `json:"clientAllowedIPs"`
	ClientPersistentKeepalive *uint16  `json:"clientPersistentKeepalive,omitempty"`
	Peers                     []Peer   `json:"peers"`
}

// InterfaceInput 是创建和更新 Interface 时允许写入的全部官方字段，
// 加上保存在 "# Name = ..." 注释中的显示名称。
type InterfaceInput struct {
	Name                      string   `json:"name"`
	PrivateKey                string   `json:"privateKey"`
	Address                   []string `json:"address"`
	ListenPort                *uint16  `json:"listenPort"`
	FwMark                    string   `json:"fwMark"`
	DNS                       []string `json:"dns"`
	MTU                       *int     `json:"mtu"`
	Table                     string   `json:"table"`
	PreUp                     []string `json:"preUp"`
	PostUp                    []string `json:"postUp"`
	PreDown                   []string `json:"preDown"`
	PostDown                  []string `json:"postDown"`
	SaveConfig                bool     `json:"saveConfig"`
	ClientEndpoint            string   `json:"clientEndpoint"`
	ClientDNS                 []string `json:"clientDNS"`
	ClientAllowedIPs          []string `json:"clientAllowedIPs"`
	ClientPersistentKeepalive *uint16  `json:"clientPersistentKeepalive"`
}

// Peer 包含 wg(8) 配置文件支持的全部 Peer 字段。
// ID、Name、PrivateKey 与客户端字段以注释形式写在所属 [Peer] 段中，
// 保持原生 WireGuard 配置兼容性。
type Peer struct {
	ID                        string   `json:"id"`
	Name                      string   `json:"name"`
	PrivateKey                string   `json:"privateKey"`
	PublicKey                 string   `json:"publicKey"`
	PresharedKey              string   `json:"presharedKey"`
	AllowedIPs                []string `json:"allowedIPs"`
	Endpoint                  string   `json:"endpoint"`
	PersistentKeepalive       *uint16  `json:"persistentKeepalive,omitempty"`
	ClientAddress             []string `json:"clientAddress"`
	ClientPersistentKeepalive *uint16  `json:"clientPersistentKeepalive,omitempty"`
	SystemGenerated           bool     `json:"systemGenerated"`
}

type PeerInput struct {
	Name                      string   `json:"name"`
	PrivateKey                string   `json:"privateKey"`
	PublicKey                 string   `json:"publicKey"`
	PresharedKey              string   `json:"presharedKey"`
	AllowedIPs                []string `json:"allowedIPs"`
	Endpoint                  string   `json:"endpoint"`
	PersistentKeepalive       *uint16  `json:"persistentKeepalive"`
	ClientAddress             []string `json:"clientAddress"`
	ClientPersistentKeepalive *uint16  `json:"clientPersistentKeepalive"`
	GenerateKeyPair           bool     `json:"generateKeyPair"`
	GeneratePresharedKey      bool     `json:"generatePresharedKey"`
}

type IPPlan struct {
	Networks  []IPNetworkPlan `json:"networks"`
	Conflicts []IPConflict    `json:"conflicts"`
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
	Kind    string `json:"kind"`
	Address string `json:"address"`
	PeerID  string `json:"peerID,omitempty"`
	Message string `json:"message"`
}
