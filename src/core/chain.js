const crypto = require('crypto');
const forge = require('node-forge');
const { parsedKeys: googlePublicKeys } = require('../config/googleKeys');

const ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';
const PROVISIONING_INFO_OID = '1.3.6.1.4.1.11129.2.1.30';

function parseCertificates(rawData) {
    if (!rawData || typeof rawData !== 'string') {
        const error = new Error('Payload missing attestation data');
        error.statusCode = 400;
        throw error;
    }
    const segments = rawData.split('.');
    if (segments.length !== 4 && segments.length !== 5) {
        const error = new Error('Invalid certificate chain length');
        error.statusCode = 400;
        throw error;
    }

    const chain = [];
    for (const segment of segments) {
        let decoded;
        try {
            decoded = Buffer.from(segment, 'base64');
        } catch (decodeError) {
            const error = new Error('Invalid base64-encoded certificate');
            error.statusCode = 400;
            throw error;
        }
        if (!decoded || decoded.length === 0) {
            const error = new Error('Empty certificate segment');
            error.statusCode = 400;
            throw error;
        }
        if (decoded.toString('base64').replace(/=+$/, '') !== segment.replace(/=+$/, '')) {
            const error = new Error('Malformed base64 certificate segment');
            error.statusCode = 400;
            throw error;
        }
        const pem = `-----BEGIN CERTIFICATE-----\n${segment}\n-----END CERTIFICATE-----`;
        try {
            chain.push({
                pem,
                cert: new crypto.X509Certificate(pem),
                metadata: inspectCertificate(pem)
            });
        } catch (parseError) {
            const error = new Error('Unable to parse certificate');
            error.statusCode = 400;
            throw error;
        }
    }

    if (!chain[0].metadata.hasAttestationExtension) {
        const error = new Error('Leaf certificate missing attestation extension');
        error.statusCode = 401;
        throw error;
    }
    for (let index = 1; index < chain.length; index += 1) {
        if (chain[index].metadata.hasAttestationExtension) {
            const error = new Error('Multiple attestation extensions detected');
            error.statusCode = 401;
            throw error;
        }
    }

    return chain;
}

function ensureRootsAvailable(roots) {
    if (!Array.isArray(roots) || roots.length === 0) {
        const error = new Error('Attestation root CA list not available');
        error.statusCode = 503;
        throw error;
    }
}

function ensureStatusAvailable(status) {
    if (!status || typeof status !== 'object' || !status.entries) {
        const error = new Error('Attestation status list not available');
        error.statusCode = 503;
        throw error;
    }
}

function verifyChain(chain, roots, enforceRemoteKeyProvision) {
    for (let i = 0; i < chain.length - 1; i += 1) {
        const child = chain[i].cert;
        const parent = chain[i + 1].cert;
        if (!child.verify(parent.publicKey)) {
            const error = new Error('Certificate signature mismatch');
            error.statusCode = 401;
            throw error;
        }
        if (!distinguishedNamesMatch(child.issuer, parent.subject)) {
            const error = new Error('Subject/issuer name chaining failed');
            error.statusCode = 401;
            throw error;
        }
    }

    const anchorEntry = chain[chain.length - 1];
    const anchor = anchorEntry.cert;
    const isSelfIssuedAnchor = isSelfSigned(anchor);

    if (!isSelfIssuedAnchor) {
        const error = new Error('Root certificate not self-signed');
        error.statusCode = 401;
        throw error;
    }

    if (!isTrustedRoot(anchor, roots) && !isSignedByGoogleKey(anchor)) {
        const error = new Error('Root certificate not recognized');
        error.statusCode = 401;
        throw error;
    }

    if (enforceRemoteKeyProvision) {
        validateProvisioningPath(chain);
    }
}

function checkRevocation(chain, status) {
    const entries = status.entries || {};
    for (const { cert } of chain.slice(0, -1)) {
        const serial = asDecimalSerial(cert);
        if (!serial) {
            continue;
        }
        const entry = entries[serial];
        if (entry && entry.status === 'REVOKED') {
            const error = new Error('Certificate has been revoked');
            error.statusCode = 401;
            throw error;
        }
    }
}

function inspectCertificate(pem) {
    try {
        const cert = forge.pki.certificateFromPem(pem);
        const extensions = cert.extensions || [];
        const extIds = new Set(extensions.map((ext) => ext.id));
        return {
            hasAttestationExtension: extIds.has(ATTESTATION_OID),
            hasProvisioningInfo: extIds.has(PROVISIONING_INFO_OID),
            provisioningMethod: classifyProvisioning(cert)
        };
    } catch (error) {
        return {
            hasAttestationExtension: false,
            hasProvisioningInfo: false,
            provisioningMethod: 'unknown'
        };
    }
}

function classifyProvisioning(forgeCert) {
    try {
        const attrs = forgeCert.subject?.attributes || [];
        const attrMap = new Map(attrs.map((attr) => [attr.type, attr.value]));

        const serial = attrMap.get('2.5.4.5');
        const title = attrMap.get('2.5.4.12');
        const commonName = attrMap.get('2.5.4.3');
        const organization = attrMap.get('2.5.4.10');

        if (serial && (title === 'TEE' || title === 'StrongBox')) {
            return 'factory';
        }

        if (commonName && organization) {
            return 'remote';
        }

        return 'unknown';
    } catch (error) {
        return 'unknown';
    }
}

function validateProvisioningPath(chain) {
    const expectsRemoteProvisioning = chain.length === 5;
    const provisioningPresent = chain
        .slice(1)
        .some((entry) => entry.metadata.hasProvisioningInfo);
    const methods = new Set(
        chain
            .slice(1)
            .map((entry) => entry.metadata.provisioningMethod)
            .filter(Boolean)
    );

    if (expectsRemoteProvisioning && !provisioningPresent) {
        const error = new Error('Remote provisioning info missing in chain');
        error.statusCode = 401;
        throw error;
    }

    if (!expectsRemoteProvisioning && provisioningPresent) {
        const error = new Error('Unexpected provisioning extension in factory chain');
        error.statusCode = 401;
        throw error;
    }

    if (!expectsRemoteProvisioning && methods.has('remote')) {
        const error = new Error('Factory chain contains remote provisioning subject');
        error.statusCode = 401;
        throw error;
    }

    if (expectsRemoteProvisioning && methods.has('factory')) {
        const error = new Error('Remote chain contains factory provisioning subject');
        error.statusCode = 401;
        throw error;
    }
}

function isSelfSigned(cert) {
    return cert.issuer === cert.subject;
}

function distinguishedNamesMatch(issuer, subject) {
    if (!issuer || !subject) {
        return false;
    }
    return normalizeDistinguishedName(issuer) === normalizeDistinguishedName(subject);
}

function normalizeDistinguishedName(value) {
    return value
        .split(/\s*\+?\,\s*/)
        .map((component) => component.trim())
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b))
        .join(',');
}

function isSignedByGoogle(cert, roots) {
    return roots.some((rootPem) => {
        try {
            const rootCert = new crypto.X509Certificate(rootPem);
            return cert.verify(rootCert.publicKey);
        } catch (error) {
            return false;
        }
    });
}

function isSignedByGoogleKey(cert) {
    return googlePublicKeys.some((publicKey) => {
        try {
            return cert.verify(publicKey);
        } catch (error) {
            return false;
        }
    });
}

function isTrustedRoot(anchor, roots) {
    const anchorFingerprint = normalizeFingerprint(anchor.fingerprint256 || anchor.fingerprint || null);
    for (const rootPem of roots) {
        try {
            const rootCert = new crypto.X509Certificate(rootPem);
            if (anchor.raw.equals(rootCert.raw)) {
                return true;
            }
            const rootFingerprint = normalizeFingerprint(rootCert.fingerprint256 || rootCert.fingerprint || null);
            if (anchorFingerprint && rootFingerprint && anchorFingerprint === rootFingerprint) {
                return true;
            }
            if (anchor.subject === rootCert.subject && anchor.verify(rootCert.publicKey)) {
                return true;
            }
        } catch (error) {
            continue;
        }
    }
    return false;
}

function normalizeFingerprint(value) {
    return value ? value.replace(/:/g, '').toUpperCase() : null;
}

function asDecimalSerial(cert) {
    try {
        if (cert.serialNumber) {
            return BigInt(`0x${cert.serialNumber}`).toString(10);
        }
    } catch (error) {
        return null;
    }
    return null;
}

module.exports = {
    parseCertificates,
    ensureRootsAvailable,
    ensureStatusAvailable,
    verifyChain,
    checkRevocation
};
