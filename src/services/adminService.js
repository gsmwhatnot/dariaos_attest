const adminStore = require('../storage/adminStore');
const adminSessionStore = require('../storage/adminSessionStore');

function createAdminService() {
    return {
        ensureAccount: () => adminStore.ensureAdminAccount(),
        verifyPassword: (password) => adminStore.verifyAdminPassword(password),
        updatePassword: (password) => adminStore.updateAdminPassword(password),
        state: () => adminStore.getAdminState(),
        createSession: () => adminSessionStore.createSession(),
        validateSession: (token) => adminSessionStore.validateSession(token),
        revokeSession: (token) => adminSessionStore.revokeSession(token)
    };
}

module.exports = createAdminService;
