const forge = require('node-forge');
const asn1 = require('asn1.js');

const EXTENSION_OID = { id: '1.3.6.1.4.1.11129.2.1.17' };

const SecurityLevel = asn1.define('SecurityLevel', function securityLevel() {
    return this.enum({
        0: 'Software',
        1: 'TrustedEnvironment',
        2: 'StrongBox'
    });
});

const VerifiedBootState = asn1.define('VerifiedBootState', function verifiedBootState() {
    return this.enum({
        0: 'Verified',
        1: 'SelfSigned',
        2: 'Unverified',
        3: 'Failed'
    });
});

const AuthorizationList = asn1.define('AuthorizationList', function authorizationList() {
    return this.seq().obj(
        this.key('purpose').explicit(1).optional().set().obj(
            this.key('purpose').int()
        ),
        this.key('algorithm').explicit(2).optional().int(),
        this.key('keySize').explicit(3).optional().int(),
        this.key('blockMode').explicit(4).optional().set().obj(
            this.key('blockMode').int()
        ),
        this.key('digest').explicit(5).optional().set().obj(
            this.key('digest').int()
        ),
        this.key('padding').explicit(6).optional().set().obj(
            this.key('padding').int()
        ),
        this.key('callerNonce').explicit(7).optional().null_(),
        this.key('minMacLength').explicit(8).optional().int(),
        this.key('ecCurve').explicit(10).optional().int(),
        this.key('rsaPublicExponent').explicit(200).optional().int(),
        this.key('rollbackResistance').explicit(303).optional().null_(),
        this.key('activeDateTime').explicit(400).optional().int(),
        this.key('originationExpireDateTime').explicit(401).optional().int(),
        this.key('usageExpireDateTime').explicit(402).optional().int(),
        this.key('userSecureId').explicit(502).optional().int(),
        this.key('noAuthRequired').explicit(503).optional().null_(),
        this.key('userAuthType').explicit(504).optional().int(),
        this.key('authTimeout').explicit(505).optional().int(),
        this.key('allowWhileOnBody').explicit(506).optional().null_(),
        this.key('trustedUserPresenceReq').explicit(507).optional().null_(),
        this.key('trustedConfirmationReq').explicit(508).optional().null_(),
        this.key('unlockedDeviceReq').explicit(509).optional().null_(),
        this.key('allApplications').explicit(600).optional().null_(),
        this.key('applicationId').explicit(601).optional().octstr(),
        this.key('creationDateTime').explicit(701).optional().int(),
        this.key('origin').explicit(702).optional().int(),
        this.key('rollbackResistant').explicit(703).optional().null_(),
        this.key('rootOfTrust').explicit(704).optional().seq().obj(
            this.key('verifiedBootKey').octstr(),
            this.key('deviceLocked').bool(),
            this.key('verifiedBootState').use(VerifiedBootState),
            this.key('verifiedBootHash').octstr()
        ),
        this.key('osVersion').explicit(705).optional().int(),
        this.key('osPatchLevel').explicit(706).optional().int(),
        this.key('attestationApplicationId').explicit(709).optional().octstr(),
        this.key('attestationIdBrand').explicit(710).optional().octstr(),
        this.key('attestationIdDevice').explicit(711).optional().octstr(),
        this.key('attestationIdProduct').explicit(712).optional().octstr(),
        this.key('attestationIdSerial').explicit(713).optional().octstr(),
        this.key('attestationIdImei').explicit(714).optional().octstr(),
        this.key('attestationIdMeid').explicit(715).optional().octstr(),
        this.key('attestationIdManufacturer').explicit(716).optional().octstr(),
        this.key('attestationIdModel').explicit(717).optional().octstr(),
        this.key('vendorPatchLevel').explicit(718).optional().int(),
        this.key('bootPatchLevel').explicit(719).optional().int(),
        this.key('deviceUniqueAttestation').explicit(720).optional().null_(),
        this.key('attestationIdSecondImei').explicit(723).optional().octstr(),
        this.key('moduleHash').explicit(724).optional().octstr()
    );
});

const KeyDescription = asn1.define('KeyDescription', function keyDescription() {
    return this.seq().obj(
        this.key('attestationVersion').int(),
        this.key('attestationSecurityLevel').use(SecurityLevel),
        this.key('keymasterVersion').int(),
        this.key('keymasterSecurityLevel').use(SecurityLevel),
        this.key('attestationChallenge').octstr(),
        this.key('uniqueId').octstr(),
        this.key('softwareEnforced').use(AuthorizationList),
        this.key('hardwareEnforced').use(AuthorizationList)
    );
});

const AttestationApplicationId = asn1.define('AttestationApplicationId', function attestationApplicationId() {
    return this.seq().obj(
        this.key('application').set().obj(
            this.key('information').seq().obj(
                this.key('packageName').octstr(),
                this.key('versionCode').int()
            )
        ),
        this.key('signature').set().obj(
            this.key('signatureDigest').optional().octstr()
        )
    );
});

function decodeAttestation(pemCert) {
    try {
        const certificate = forge.pki.certificateFromPem(pemCert);
        const extension = certificate.getExtension(EXTENSION_OID);
        if (!extension) {
            return null;
        }
        const decoded = KeyDescription.decode(Buffer.from(extension.value, 'binary'), 'der');
        decoded.softwareEnforced.attestationApplicationId = decoded.softwareEnforced.attestationApplicationId
            ? AttestationApplicationId.decode(decoded.softwareEnforced.attestationApplicationId, 'der')
            : null;
        return simplify(decoded);
    } catch (error) {
        // eslint-disable-next-line no-console
        console.warn('[decode][failure]', error.message);
        return null;
    }
}

function simplify(decoded) {
    const software = decoded.softwareEnforced || {};
    const hardware = decoded.hardwareEnforced || {};

    const app = software.attestationApplicationId;

    const challengeBuffer = Buffer.from(decoded.attestationChallenge);
    const challengeText = bufferToPrintableUtf8(challengeBuffer);

    return {
        attestVersion: toSafeNumber(decoded.attestationVersion),
        attestSecurity: decoded.attestationSecurityLevel,
        keymasterVersion: toSafeNumber(decoded.keymasterVersion),
        keymasterSecurity: decoded.keymasterSecurityLevel,
        attestChallenge: challengeText,
        attestChallengeRaw: challengeBuffer,
        attestDate: software.creationDateTime ? toSafeNumber(software.creationDateTime) : null,
        uniqueId: bufferToHex(decoded.uniqueId),
        hardwareOrigin: resolveOrigin(hardware.origin),
        softwareOrigin: resolveOrigin(software.origin),
        attestationIds: buildAttestationIds(software),
        rootOfTrust: hardware.rootOfTrust
            ? {
                  verifiedBootKey: bufferToHex(hardware.rootOfTrust.verifiedBootKey),
                  deviceLocked: hardware.rootOfTrust.deviceLocked,
                  verifiedBootState: hardware.rootOfTrust.verifiedBootState,
                  verifiedBootHash: bufferToHex(hardware.rootOfTrust.verifiedBootHash)
              }
            : null,
        application: app
            ? {
                  packageName: safeString(app.application.information.packageName),
                  versionCode: toSafeNumber(app.application.information.versionCode),
                  signatureDigest: app.signature.signatureDigest
                      ? bufferToHex(app.signature.signatureDigest)
                      : null
              }
            : null,
        softwareEnforced: flattenAuthorizationList(software),
        hardwareEnforced: flattenAuthorizationList(hardware),
        original: decoded
    };
}

function buildAttestationIds(list) {
    return {
        brand: safeString(list.attestationIdBrand),
        device: safeString(list.attestationIdDevice),
        product: safeString(list.attestationIdProduct),
        serial: safeString(list.attestationIdSerial),
        imei: safeString(list.attestationIdImei),
        secondImei: safeString(list.attestationIdSecondImei),
        meid: safeString(list.attestationIdMeid),
        manufacturer: safeString(list.attestationIdManufacturer),
        model: safeString(list.attestationIdModel)
    };
}

function flattenAuthorizationList(list) {
    if (!list) {
        return {};
    }
    const out = {};
    for (const [key, value] of Object.entries(list)) {
        if (value === undefined || value === null) {
            continue;
        }
        if (Buffer.isBuffer(value)) {
            out[key] = bufferToHex(value);
            continue;
        }
        if (value instanceof Set) {
            out[key] = Array.from(value).map((item) => toSafeNumber(item));
            continue;
        }
        if (Array.isArray(value)) {
            out[key] = value.map((item) => (Buffer.isBuffer(item) ? bufferToHex(item) : toSafeNumber(item)));
            continue;
        }
        if (typeof value === 'object' && typeof value.toNumber === 'function') {
            out[key] = toSafeNumber(value);
            continue;
        }
        out[key] = value;
    }
    return out;
}

function bufferToHex(value) {
    if (!value) {
        return null;
    }
    if (Buffer.isBuffer(value)) {
        return value.toString('hex');
    }
    if (value.valueBlock && value.valueBlock.valueHex) {
        return Buffer.from(value.valueBlock.valueHex).toString('hex');
    }
    return null;
}

function safeString(value) {
    if (!value) {
        return null;
    }
    if (Buffer.isBuffer(value)) {
        return bufferToPrintableUtf8(value);
    }
    if (typeof value === 'string') {
        return value;
    }
    if (value.valueBlock && value.valueBlock.valueHex) {
        return bufferToPrintableUtf8(Buffer.from(value.valueBlock.valueHex));
    }
    if (typeof value.toString === 'function') {
        try {
            return value.toString();
        } catch (error) {
            return null;
        }
    }
    return null;
}

function toSafeNumber(value) {
    if (value === null || value === undefined) {
        return null;
    }
    if (typeof value === 'number') {
        return Number.isFinite(value) ? value : null;
    }
    if (typeof value === 'bigint') {
        const num = Number(value);
        return Number.isFinite(num) ? num : null;
    }
    if (typeof value.toNumber === 'function') {
        try {
            const result = value.toNumber();
            return Number.isFinite(result) ? result : null;
        } catch (error) {
            return null;
        }
    }
    return null;
}

function bufferToPrintableUtf8(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        return null;
    }
    try {
        const text = buffer.toString('utf8');
        if (!Buffer.from(text, 'utf8').equals(buffer)) {
            return null;
        }
        if (/[^\x20-\x7E]/.test(text)) {
            return null;
        }
        return text;
    } catch (error) {
        return null;
    }
}

function resolveOrigin(value) {
    const originNumber = toSafeNumber(value);
    if (originNumber === null || originNumber === undefined) {
        return null;
    }
    switch (originNumber) {
        case 0:
            return 'Generated';
        case 1:
            return 'Derived';
        case 2:
            return 'Imported';
        case 3:
            return 'Reserved';
        case 4:
            return 'SecurelyImported';
        default:
            return String(originNumber);
    }
}

module.exports = {
    decodeAttestation
};
