const { verifyAttestation } = require('../core/attestation');

function createAttestationService({
    initialRoots = [],
    initialStatus = null,
    attestationTimeoutMs = 600000,
    attestationTimeoutSeconds = 600
} = {}) {
    const normalizedTimeoutMs = Number.isFinite(attestationTimeoutMs) && attestationTimeoutMs >= 0
        ? attestationTimeoutMs
        : 600000;
    const normalizedTimeoutSeconds = Number.isFinite(attestationTimeoutSeconds) && attestationTimeoutSeconds >= 0
        ? attestationTimeoutSeconds
        : Math.round(normalizedTimeoutMs / 1000);

    const state = {
        roots: initialRoots,
        status: initialStatus,
        timeoutMs: normalizedTimeoutMs,
        timeoutSeconds: normalizedTimeoutSeconds
    };

    function updateRoots(roots) {
        state.roots = Array.isArray(roots) ? roots : [];
    }

    function updateStatus(status) {
        state.status = status || null;
    }

    function getRoots() {
        return state.roots;
    }

    function getStatus() {
        return state.status;
    }

    function isReady() {
        return Array.isArray(state.roots) && state.roots.length > 0 && !!state.status;
    }

    async function verify(options) {
        return verifyAttestation({
            ...options,
            roots: state.roots,
            status: state.status,
            attestationTimeoutMs: state.timeoutMs,
            attestationTimeoutSeconds: state.timeoutSeconds
        });
    }

    return {
        updateRoots,
        updateStatus,
        getRoots,
        getStatus,
        isReady,
        verify
    };
}

module.exports = createAttestationService;
