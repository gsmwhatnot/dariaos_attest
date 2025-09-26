const {
    parseCertificates,
    ensureRootsAvailable,
    ensureStatusAvailable,
    verifyChain,
    checkRevocation
} = require('./chain');
const {
    extractDeviceInfo,
    formatDeviceForLog,
    buildDeviceSerialKey,
    resolveDeviceModel
} = require('./device');
const { evaluate } = require('./evaluation');
const { normalizeDebug, formatAttestationDebug } = require('./debug');
const { buildKeyDescriptionSnapshot } = require('./snapshot');
const { decodeAttestation } = require('./attestationDecoder');
const { maskApiKey } = require('./utils');
const { ENFORCE_REMOTE_KEY_PROVISION } = require('../config');

async function verifyAttestation({
    chainData,
    apiKey,
    roots,
    status,
    attestationTimeoutMs,
    attestationTimeoutSeconds,
    enableDebug = false
}) {
    ensureRootsAvailable(roots);
    ensureStatusAvailable(status);

    const timeoutMs = Number.isFinite(attestationTimeoutMs) && attestationTimeoutMs >= 0
        ? attestationTimeoutMs
        : 600000;
    const timeoutSeconds = Number.isFinite(attestationTimeoutSeconds) && attestationTimeoutSeconds >= 0
        ? attestationTimeoutSeconds
        : Math.round(timeoutMs / 1000);

    const chain = parseCertificates(chainData);
    verifyChain(chain, roots, ENFORCE_REMOTE_KEY_PROVISION);
    checkRevocation(chain, status);

    let attestation = null;
    for (const entry of chain) {
        attestation = decodeAttestation(entry.pem);
        if (attestation) {
            break;
        }
    }
    if (!attestation) {
        const error = new Error('Attestation extension missing');
        error.statusCode = 401;
        throw error;
    }

    const device = extractDeviceInfo(attestation);
    const evaluation = evaluate(attestation, device.warrantyValid, timeoutMs, timeoutSeconds);

    const debug = enableDebug ? normalizeDebug(attestation) : null;
    const deviceSerialKey = buildDeviceSerialKey(device, attestation);
    const deviceModelValue = resolveDeviceModel(device, attestation);
    const keyDescriptionSnapshot = buildKeyDescriptionSnapshot(attestation);

    return {
        success: evaluation.valid,
        reasons: evaluation.reasons,
        device,
        attestation,
        debug,
        deviceLog: deviceSerialKey && keyDescriptionSnapshot
            ? {
                serial: deviceSerialKey,
                model: deviceModelValue,
                snapshot: keyDescriptionSnapshot
            }
            : null,
        response: evaluation.valid
            ? { reason: 'Authorized', errorcode: 200 }
            : { reason: 'Unauthorized', errorcode: 401 },
        log: {
            event: 'verify',
            status: evaluation.valid ? 200 : 401,
            reason: evaluation.valid ? 'Authorized' : 'Unauthorized',
            api: {
                key: maskApiKey(apiKey),
                label: ''
            },
            device: formatDeviceForLog(device),
            evaluationIssues: evaluation.valid ? [] : evaluation.reasons,
            error: '',
            policy: {
                attestationTimeoutSeconds: timeoutSeconds
            }
        }
    };
}

module.exports = {
    verifyAttestation,
    maskApiKey,
    formatAttestationDebug
};

