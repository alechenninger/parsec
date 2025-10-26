package keymanager

import (
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	spirekm "github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/awskms"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/azurekeyvault"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/disk"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/gcpkms"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
)

// keyManagerRepository implements the catalog.PluginRepo interface for KeyManagers
type keyManagerRepository struct {
	spirekm.Repository
}

// Binder returns the function used to bind the KeyManager to the repository
func (repo *keyManagerRepository) Binder() any {
	return repo.SetKeyManager
}

// Constraints returns ExactlyOne, meaning exactly one KeyManager must be configured
func (repo *keyManagerRepository) Constraints() catalog.Constraints {
	return catalog.ExactlyOne()
}

// Versions returns the supported versions for KeyManager
func (repo *keyManagerRepository) Versions() []catalog.Version {
	return []catalog.Version{keyManagerV1{}}
}

// BuiltIns returns the list of built-in KeyManager plugins from Spire
func (repo *keyManagerRepository) BuiltIns() []catalog.BuiltIn {
	return []catalog.BuiltIn{
		awskms.BuiltIn(),
		disk.BuiltIn(),
		gcpkms.BuiltIn(),
		azurekeyvault.BuiltIn(),
		memory.BuiltIn(),
	}
}

// keyManagerV1 represents the v1 version of the KeyManager plugin interface
type keyManagerV1 struct{}

func (keyManagerV1) New() catalog.Facade { return new(spirekm.V1) }
func (keyManagerV1) Deprecated() bool    { return false }

// ParsecCatalogRepository implements the catalog.Repository interface
// It only handles KeyManager plugins (no other plugin types or services)
type ParsecCatalogRepository struct {
	keyManagerRepository
}

// Plugins returns the plugin repositories, just KeyManager for Parsec
func (repo *ParsecCatalogRepository) Plugins() map[string]catalog.PluginRepo {
	return map[string]catalog.PluginRepo{
		"KeyManager": &repo.keyManagerRepository,
	}
}

// Services returns service repositories (none for Parsec)
func (repo *ParsecCatalogRepository) Services() []catalog.ServiceRepo {
	return nil
}

// GetKeyManager retrieves the loaded KeyManager from the repository
func (repo *ParsecCatalogRepository) GetKeyManager() spirekm.KeyManager {
	return repo.keyManagerRepository.KeyManager
}

// LoadKeyManagerFromHCL loads a KeyManager plugin using Spire's catalog system
// The pluginHCL should be HCL configuration for the KeyManager plugin, e.g.:
//
//	KeyManager "memory" {
//	  plugin_data {}
//	}
func LoadKeyManagerFromHCL(ctx context.Context, pluginHCL string, log logrus.FieldLogger) (spirekm.KeyManager, io.Closer, error) {
	// Parse the HCL configuration
	var hclConfig struct {
		Plugins ast.Node `hcl:"plugins"`
	}

	// Wrap the plugin config in a "plugins" block as expected by catalog
	wrappedHCL := fmt.Sprintf("plugins {\n%s\n}", pluginHCL)

	if err := hcl.Decode(&hclConfig, wrappedHCL); err != nil {
		return nil, nil, fmt.Errorf("failed to parse plugin HCL: %w", err)
	}

	// Convert HCL to PluginConfigs
	pluginConfigs, err := catalog.PluginConfigsFromHCLNode(hclConfig.Plugins)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse plugin configs: %w", err)
	}

	// Create the repository
	repo := &ParsecCatalogRepository{}

	// Use a minimal trust domain for the catalog (required but not used by KeyManager)
	trustDomain, err := spiffeid.TrustDomainFromString("example.org")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create trust domain: %w", err)
	}

	// Load the catalog
	cat, err := catalog.Load(ctx, catalog.Config{
		Log:           log,
		PluginConfigs: pluginConfigs,
		HostServices:  nil, // No host services needed for KeyManager
		CoreConfig: catalog.CoreConfig{
			TrustDomain: trustDomain,
		},
	}, repo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load catalog: %w", err)
	}

	// Get the loaded KeyManager
	km := repo.GetKeyManager()
	if km == nil {
		cat.Close()
		return nil, nil, fmt.Errorf("no KeyManager was loaded")
	}

	return km, cat, nil
}
