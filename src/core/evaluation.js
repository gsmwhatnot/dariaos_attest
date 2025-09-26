function evaluate(attestation, warrantyValid, timeoutMs, timeoutSeconds) {
    if (!attestation) {
        return {
            valid: false,
            reasons: ['Attestation extension missing']
        };
    }
    const issues = [];

    if (attestation.attestSecurity !== 'TrustedEnvironment') {
        issues.push('Attestation security level not TrustedEnvironment');
    }
    if (attestation.keymasterSecurity !== 'TrustedEnvironment') {
        issues.push('Keymaster security level not TrustedEnvironment');
    }
    if (attestation.attestSecurity && attestation.keymasterSecurity && attestation.attestSecurity !== attestation.keymasterSecurity) {
        issues.push('Attestation/keymaster security level mismatch');
    }
    if (attestation.hardwareOrigin && attestation.hardwareOrigin !== 'Generated') {
        issues.push(`Hardware origin ${attestation.hardwareOrigin} not allowed`);
    }
    if (!attestation.rootOfTrust || attestation.rootOfTrust.deviceLocked !== true) {
        issues.push('Device reported unlocked');
    }
    if (!attestation.rootOfTrust || attestation.rootOfTrust.verifiedBootState !== 'Verified') {
        issues.push('Verified boot state not Verified');
    }
    const enforceFreshness = Number.isFinite(timeoutMs) && timeoutMs > 0;
    const timeoutLabel = Number.isFinite(timeoutSeconds) && timeoutSeconds >= 0
        ? timeoutSeconds
        : Math.round((timeoutMs || 0) / 1000);

    if (typeof attestation.attestDate === 'number') {
        const drift = Math.abs(Date.now() - attestation.attestDate);
        if (enforceFreshness && drift > timeoutMs) {
            issues.push(`Attestation older than ${timeoutLabel} seconds`);
        }
    } else {
        issues.push('Attestation timestamp missing');
    }
    if (warrantyValid === false) {
        issues.push('Warranty flag revoked');
    }

    return {
        valid: issues.length === 0,
        reasons: issues
    };
}

module.exports = {
    evaluate
};

