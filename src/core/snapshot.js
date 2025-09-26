const { AUTHORIZATION_FIELDS } = require('./debug');
const { describeChallengeBuffer } = require('./device');

function buildKeyDescriptionSnapshot(attestation) {
    if (!attestation) {
        return null;
    }
    const bufferDescriptor = describeChallengeBuffer(attestation.attestChallengeRaw);
    return {
        attestationVersion: attestation.attestVersion ?? null,
        attestationSecurityLevel: attestation.attestSecurity ?? null,
        keymasterVersion: attestation.keymasterVersion ?? null,
        keymasterSecurityLevel: attestation.keymasterSecurity ?? null,
        attestationChallenge: bufferDescriptor,
        uniqueId: attestation.uniqueId ?? null,
        softwareEnforced: buildAuthorizationSnapshot(attestation.softwareEnforced),
        hardwareEnforced: buildAuthorizationSnapshot(attestation.hardwareEnforced)
    };
}

function buildAuthorizationSnapshot(list) {
    const snapshot = {};
    for (const field of AUTHORIZATION_FIELDS) {
        const value = list && Object.prototype.hasOwnProperty.call(list, field.key)
            ? list[field.key]
            : null;
        snapshot[field.key] = value ?? null;
    }
    return snapshot;
}

module.exports = {
    buildKeyDescriptionSnapshot
};

