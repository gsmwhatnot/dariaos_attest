const { bufferToPrintable } = require('./utils');

const AUTHORIZATION_FIELDS = [
    { key: 'purpose', label: 'purpose' },
    { key: 'algorithm', label: 'algorithm' },
    { key: 'keySize', label: 'keySize' },
    { key: 'blockMode', label: 'blockMode' },
    { key: 'digest', label: 'digest' },
    { key: 'padding', label: 'padding' },
    { key: 'callerNonce', label: 'callerNonce' },
    { key: 'minMacLength', label: 'minMacLength' },
    { key: 'ecCurve', label: 'ecCurve' },
    { key: 'rsaPublicExponent', label: 'rsaPublicExponent' },
    { key: 'rollbackResistance', label: 'rollbackResistance' },
    { key: 'activeDateTime', label: 'activeDateTime' },
    { key: 'originationExpireDateTime', label: 'originationExpireDateTime' },
    { key: 'usageExpireDateTime', label: 'usageExpireDateTime' },
    { key: 'userSecureId', label: 'userSecureId' },
    { key: 'noAuthRequired', label: 'noAuthRequired' },
    { key: 'userAuthType', label: 'userAuthType' },
    { key: 'authTimeout', label: 'authTimeout' },
    { key: 'allowWhileOnBody', label: 'allowWhileOnBody' },
    { key: 'trustedUserPresenceReq', label: 'trustedUserPresenceReq' },
    { key: 'trustedConfirmationReq', label: 'trustedConfirmationReq' },
    { key: 'unlockedDeviceReq', label: 'unlockedDeviceReq' },
    { key: 'creationDateTime', label: 'creationDateTime' },
    { key: 'origin', label: 'origin' },
    { key: 'rootOfTrust', label: 'rootOfTrust' },
    { key: 'osVersion', label: 'osVersion' },
    { key: 'osPatchLevel', label: 'osPatchLevel' },
    { key: 'attestationApplicationId', label: 'attestationApplicationId' },
    { key: 'attestationIdBrand', label: 'attestationIdBrand' },
    { key: 'attestationIdDevice', label: 'attestationIdDevice' },
    { key: 'attestationIdProduct', label: 'attestationIdProduct' },
    { key: 'attestationIdSerial', label: 'attestationIdSerial' },
    { key: 'attestationIdImei', label: 'attestationIdImei' },
    { key: 'attestationIdMeid', label: 'attestationIdMeid' },
    { key: 'attestationIdManufacturer', label: 'attestationIdManufacturer' },
    { key: 'attestationIdModel', label: 'attestationIdModel' },
    { key: 'vendorPatchLevel', label: 'vendorPatchLevel' },
    { key: 'bootPatchLevel', label: 'bootPatchLevel' },
    { key: 'deviceUniqueAttestation', label: 'deviceUniqueAttestation' },
    { key: 'attestationIdSecondImei', label: 'attestationIdSecondImei' },
    { key: 'moduleHash', label: 'moduleHash' }
];

const TOP_FIELD_ORDER = [
    { key: 'attestationVersion', label: 'attestationVersion', quote: false },
    { key: 'attestationSecurityLevel', label: 'attestationSecurityLevel', quote: false },
    { key: 'keymasterVersion', label: 'keymasterVersion', quote: false },
    { key: 'keymasterSecurityLevel', label: 'keymasterSecurityLevel', quote: false },
    { key: 'attestationChallenge', label: 'attestationChallenge', quote: true },
    { key: 'uniqueId', label: 'uniqueId', quote: true }
];

function normalizeDebug(attestation) {
    if (!attestation?.original) {
        return null;
    }
    const seen = new WeakSet();
    const helper = (value, path = []) => {
        if (Buffer.isBuffer(value)) {
            const key = path[path.length - 1];
            return describeBuffer(value, key === 'attestationChallenge');
        }
        if (typeof value === 'bigint') {
            return value.toString();
        }
        if (typeof value?.toNumber === 'function') {
            try {
                const numberValue = value.toNumber();
                if (Number.isSafeInteger(numberValue)) {
                    return numberValue;
                }
                return value.toString();
            } catch (error) {
                return value.toString();
            }
        }
        if (Array.isArray(value)) {
            return value.map((item, index) => helper(item, path.concat(String(index))));
        }
        if (value && typeof value === 'object') {
            if (seen.has(value)) {
                return '[Circular]';
            }
            seen.add(value);
            const out = {};
            for (const [key, nested] of Object.entries(value)) {
                out[key] = helper(nested, path.concat(key));
            }
            seen.delete(value);
            return out;
        }
        return value;
    };
    return {
        KeyDescription: helper(attestation.original)
    };
}

function describeBuffer(buffer, preferText = false) {
    const text = bufferToPrintable(buffer);
    if (preferText && text !== null) {
        return text;
    }
    const description = {
        length: buffer.length,
        base64: buffer.toString('base64'),
        hex: buffer.toString('hex')
    };
    if (text !== null) {
        description.text = text;
    }
    return description;
}

function formatAttestationDebug(debugTree) {
    if (!debugTree?.KeyDescription) {
        return '[debug][cert0] (no attestation data)';
    }
    const kd = debugTree.KeyDescription;
    const lines = ['[debug][cert0]', 'KeyDescription'];
    const topLabelWidth = 30;
    for (const field of TOP_FIELD_ORDER) {
        const value = kd[field.key];
        const rendered = formatValue(value, { quoteStrings: field.quote });
        lines.push(`  • ${field.label.padEnd(topLabelWidth)}: ${rendered}`);
    }
    lines.push(...formatAuthorizationList('softwareEnforced', kd.softwareEnforced || {}));
    lines.push(...formatAuthorizationList('hardwareEnforced', kd.hardwareEnforced || {}));
    return lines.join('\n');
}

function formatAuthorizationList(label, list) {
    const lines = [`  ${label}`];
    const indent = '    ';
    const fieldIndent = `${indent}• `;
    const labelWidth = 32;
    for (const field of AUTHORIZATION_FIELDS) {
        const hasField = Object.prototype.hasOwnProperty.call(list, field.key);
        if (field.key === 'rootOfTrust' && hasField) {
            lines.push(`${fieldIndent}${field.label.padEnd(labelWidth)}:`);
            const detailWidth = 28;
            const nested = list[field.key] || {};
            lines.push(`${indent}    • ${'verifiedBootKey'.padEnd(detailWidth)}: ${formatValue(nested.verifiedBootKey)}`);
            lines.push(`${indent}    • ${'deviceLocked'.padEnd(detailWidth)}: ${formatValue(nested.deviceLocked)}`);
            lines.push(`${indent}    • ${'verifiedBootState'.padEnd(detailWidth)}: ${formatValue(nested.verifiedBootState)}`);
            lines.push(`${indent}    • ${'verifiedBootHash'.padEnd(detailWidth)}: ${formatValue(nested.verifiedBootHash)}`);
            continue;
        }
        if (field.key === 'attestationApplicationId' && hasField) {
            const app = list[field.key] || {};
            lines.push(`${fieldIndent}${field.label.padEnd(labelWidth)}:`);
            const subBullet = `${indent}    • `;
            const subPlain = `${indent}      `;
            const info = app.application?.information || {};
            const signature = app.signature || {};
            const detailWidth = 28;
            lines.push(`${subBullet}${'packageName'.padEnd(detailWidth)}: ${formatValue(info.packageName, { quoteStrings: true })}`);
            lines.push(`${subBullet}${'versionCode'.padEnd(detailWidth)}: ${formatValue(info.versionCode)}`);
            pushBufferDetails(lines, subBullet, subPlain, 'signatureDigest', signature.signatureDigest);
            continue;
        }
        const rendered = hasField ? formatValue(list[field.key]) : '(absent)';
        lines.push(`${fieldIndent}${field.label.padEnd(labelWidth)}: ${rendered}`);
    }
    return lines;
}

function pushBufferDetails(lines, indentBullet, indentPlain, label, descriptor) {
    if (!isBufferDescriptor(descriptor)) {
        lines.push(`${indentBullet}${label.padEnd(28)}: ${formatValue(descriptor)}`);
        return;
    }
    if (descriptor.text) {
        const textLabel = `${label} (text)`;
        lines.push(`${indentBullet}${textLabel.padEnd(28)}: "${descriptor.text}"`);
    }
    const hexLabel = `${label} (hex)`;
    const b64Label = `${label} (b64)`;
    lines.push(`${indentBullet}${hexLabel.padEnd(28)}: ${descriptor.hex || '(absent)'}`);
    lines.push(`${indentPlain}${b64Label.padEnd(28)}: ${descriptor.base64 || '(absent)'}`);
}

function isBufferDescriptor(value) {
    return value && typeof value === 'object' && 'hex' in value && 'base64' in value && 'length' in value;
}

function renderBufferDescriptor(descriptor) {
    if (!isBufferDescriptor(descriptor)) {
        return formatValue(descriptor);
    }
    if (descriptor.length === 0) {
        return '(empty)';
    }
    const parts = [];
    if (descriptor.text) {
        parts.push(`"${descriptor.text}"`);
    }
    if (descriptor.hex) {
        parts.push(`hex:${descriptor.hex}`);
    }
    if (descriptor.base64) {
        parts.push(`base64:${descriptor.base64}`);
    }
    return parts.join(' | ') || 'present';
}

function formatValue(value, { quoteStrings = false } = {}) {
    if (value === undefined) {
        return '(absent)';
    }
    if (value === null) {
        return 'present';
    }
    if (typeof value === 'string') {
        return quoteStrings ? `"${value}"` : value;
    }
    if (typeof value === 'number' || typeof value === 'bigint') {
        return String(value);
    }
    if (typeof value === 'boolean') {
        return value ? 'true' : 'false';
    }
    if (Array.isArray(value)) {
        if (value.length === 0) {
            return '[]';
        }
        return `[${value.map((item) => formatValue(item, { quoteStrings })).join(', ')}]`;
    }
    if (isBufferDescriptor(value)) {
        return renderBufferDescriptor(value);
    }
    if (value && typeof value === 'object') {
        const keys = Object.keys(value);
        if (keys.length === 1) {
            const soleValue = value[keys[0]];
            if (Array.isArray(soleValue)) {
                if (soleValue.length === 0) {
                    return '[]';
                }
                return `[${soleValue.map((item) => formatValue(item, { quoteStrings })).join(', ')}]`;
            }
            if (typeof soleValue === 'number' || typeof soleValue === 'string' || typeof soleValue === 'boolean') {
                return formatValue(soleValue, { quoteStrings });
            }
        }
        return JSON.stringify(value);
    }
    return String(value);
}

module.exports = {
    AUTHORIZATION_FIELDS,
    normalizeDebug,
    formatAttestationDebug
};

