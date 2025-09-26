const { safeString, bufferToPrintable } = require('./utils');

function extractDeviceInfo(attestation) {
    if (!attestation) {
        return {
            warrantyValid: null,
            deviceSerial: null,
            deviceModel: null,
            manufacturer: null,
            warrantyRaw: null
        };
    }
    const ids = attestation.attestationIds || {};
    let deviceSerial = ids.serial || null;
    let deviceModel = ids.model || ids.product || null;
    let warrantyValid = null;
    let warrantyRaw = null;

    if (attestation.attestChallenge) {
        const [warrantyFlag, serialFromChallenge] = attestation.attestChallenge.split(',');
        if (warrantyFlag) {
            warrantyRaw = warrantyFlag;
            warrantyValid = warrantyFlag === '1';
        }
        if (serialFromChallenge) {
            const payload = serialFromChallenge.trim();
            const modelCandidate = payload.length >= 8 ? payload.slice(0, 8) : null;
            const serialCandidate = payload.length > 8 ? payload.slice(8) : payload;

            if (!deviceModel && modelCandidate) {
                deviceModel = modelCandidate;
            }
            if (!deviceSerial && serialCandidate) {
                deviceSerial = serialCandidate;
            }
        }
    }

    return {
        warrantyValid,
        deviceSerial,
        deviceModel,
        manufacturer: ids.manufacturer || null,
        warrantyRaw
    };
}

function formatDeviceForLog(device) {
    return {
        model: safeString(device.deviceModel ?? device.model ?? ''),
        serial: safeString(device.deviceSerial ?? device.serial ?? ''),
        manufacturer: safeString(device.manufacturer ?? ''),
        warrantyFlag: safeString(device.warrantyRaw ?? device.warrantyFlag ?? '')
    };
}

function buildDeviceSerialKey(device, attestation) {
    const serial = safeString(device?.deviceSerial ?? device?.serial ?? attestation?.attestationIds?.serial ?? '');
    if (!serial) {
        return null;
    }
    return serial;
}

function resolveDeviceModel(device, attestation) {
    return safeString(device?.deviceModel ?? device?.model ?? attestation?.attestationIds?.model ?? '');
}

function describeChallengeBuffer(buffer) {
    if (!buffer || buffer.length === 0) {
        return {
            text: '',
            base64: '',
            hex: ''
        };
    }
    const text = bufferToPrintable(buffer);
    return {
        text: typeof text === 'string' ? text : '',
        base64: buffer.toString('base64'),
        hex: buffer.toString('hex')
    };
}

module.exports = {
    extractDeviceInfo,
    formatDeviceForLog,
    buildDeviceSerialKey,
    resolveDeviceModel,
    describeChallengeBuffer
};

