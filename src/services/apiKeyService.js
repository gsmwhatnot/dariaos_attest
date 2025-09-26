const apiKeyStore = require('../storage/apiKeyStore');

function createApiKeyService() {
    return {
        list: () => apiKeyStore.listKeys(),
        create: (label) => apiKeyStore.createKey(label),
        revoke: (id) => apiKeyStore.revokeKey(id),
        remove: (id, label) => apiKeyStore.removeKey(id, label),
        verify: (apiKey) => apiKeyStore.verifyKey(apiKey),
        setDisabled: (id, disabled) => apiKeyStore.setDisabled(id, disabled)
    };
}

module.exports = createApiKeyService;
