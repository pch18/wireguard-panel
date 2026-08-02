package wgconfig

import (
	"context"

	"wireguard-panel/internal/model"
)

// These compatibility helpers keep file-focused tests concise without
// shipping the retired mutation API. Production writes use only Applied
// methods, including file-only development mode.
func (store *Store) Create(id string, input model.InterfaceInput) (model.Interface, error) {
	return store.CreateApplied(context.Background(), id, input, FileOnlyTunnelController{})
}

func (store *Store) Import(data []byte) (model.Interface, error) {
	return store.ImportApplied(context.Background(), data, FileOnlyTunnelController{})
}

func (store *Store) Update(
	id string,
	expectedRevision string,
	input model.InterfaceInput,
) (model.Interface, error) {
	return store.UpdateApplied(
		context.Background(), id, expectedRevision, input, FileOnlyTunnelController{}, false,
	)
}

func (store *Store) ImportOver(
	id string,
	expectedRevision string,
	data []byte,
) (model.Interface, error) {
	return store.ImportOverApplied(
		context.Background(), id, expectedRevision, data, FileOnlyTunnelController{}, false,
	)
}

func (store *Store) Delete(id string, expectedRevision string) error {
	return store.DeleteApplied(
		context.Background(), id, expectedRevision, FileOnlyTunnelController{},
	)
}

func (store *Store) AddPeer(
	id string,
	expectedRevision string,
	input model.PeerInput,
) (model.Interface, error) {
	return store.AddPeerApplied(
		context.Background(), id, expectedRevision, input, FileOnlyTunnelController{}, false,
	)
}

func (store *Store) ImportPeer(
	id string,
	expectedRevision string,
	data []byte,
) (model.Interface, error) {
	return store.ImportPeerApplied(
		context.Background(), id, expectedRevision, data, FileOnlyTunnelController{}, false,
	)
}

func (store *Store) UpdatePeer(
	interfaceID string,
	originalPublicKey string,
	expectedRevision string,
	input model.PeerInput,
) (model.Interface, error) {
	return store.UpdatePeerApplied(
		context.Background(),
		interfaceID,
		originalPublicKey,
		expectedRevision,
		input,
		FileOnlyTunnelController{},
		false,
	)
}

func (store *Store) DeletePeer(
	interfaceID string,
	publicKey string,
	expectedRevision string,
) (model.Interface, error) {
	return store.DeletePeerApplied(
		context.Background(),
		interfaceID,
		publicKey,
		expectedRevision,
		FileOnlyTunnelController{},
		false,
	)
}
