const https = require('https');
const { ensureDir } = require('../storage/file');
const {
    DATA_DIR,
    LOGS_DIR,
    SITE_NAME,
    BASE_PATH,
    BASE_ORIGIN,
    resolveAppPath,
    GOOGLE_ROOTS_URL,
    GOOGLE_STATUS_URL,
    ROOT_REFRESH_INTERVAL_MS,
    ATTESTATION_TIMEOUT_SECONDS,
    ATTESTATION_TIMEOUT_MS,
    SESSION_SECRET,
    ENFORCE_API_KEY
} = require('../config');
const { googleCache } = require('../storage');
const createLoggerService = require('./loggerService');
const createAdminService = require('./adminService');
const createApiKeyService = require('./apiKeyService');
const createAttestationService = require('./attestationService');
const fallbackRoots = require('../config/googleRoots');

async function bootstrapServices() {
    await ensureDir(DATA_DIR);
    await ensureDir(LOGS_DIR);

    const logger = createLoggerService();
    const admin = createAdminService();
    await admin.ensureAccount();

    let cachedRoots = await googleCache.loadRoots();
    if (!Array.isArray(cachedRoots) || cachedRoots.length === 0) {
        cachedRoots = fallbackRoots;
    }
    const cachedStatus = await googleCache.loadStatus();

    const attestation = createAttestationService({
        initialRoots: cachedRoots,
        initialStatus: cachedStatus,
        attestationTimeoutMs: ATTESTATION_TIMEOUT_MS,
        attestationTimeoutSeconds: ATTESTATION_TIMEOUT_SECONDS
    });

    const apiKeys = createApiKeyService();

    const flags = {
        debugAttestation: process.env.DEBUG_ATTESTATION === '1'
    };

    async function refreshGoogleData() {
        try {
            const [rootsResponse, statusResponse] = await Promise.all([
                fetchText(GOOGLE_ROOTS_URL),
                fetchJson(GOOGLE_STATUS_URL)
            ]);

            if (rootsResponse) {
                const parsedRoots = parseRootsPayload(rootsResponse);
                if (parsedRoots.length > 0) {
                    await googleCache.saveRoots(parsedRoots);
                    attestation.updateRoots(parsedRoots);
                }
            }

            if (statusResponse) {
                await googleCache.saveStatus(statusResponse);
                attestation.updateStatus(statusResponse);
            }

            return true;
        } catch (error) {
            // eslint-disable-next-line no-console
            console.error('Failed to refresh Google attestation data', error.message);
            if (!attestation.isReady()) {
                attestation.updateRoots(fallbackRoots);
            }
            return false;
        }
    }

    // Attempt to refresh on startup, but keep cached data if call fails.
    refreshGoogleData();
    const refreshTimer = setInterval(refreshGoogleData, ROOT_REFRESH_INTERVAL_MS);
    if (typeof refreshTimer.unref === 'function') {
        refreshTimer.unref();
    }

    return {
        logger,
        admin,
        apiKeys,
        attestation,
        flags,
        config: {
            SITE_NAME,
            BASE_PATH,
            BASE_ORIGIN,
            resolveAppPath,
            attestationTimeoutSeconds: ATTESTATION_TIMEOUT_SECONDS,
            sessionSecret: SESSION_SECRET,
            enforceApiKey: ENFORCE_API_KEY
        },
        google: {
            refresh: refreshGoogleData
        },
        timers: [refreshTimer]
    };
}

function parseRootsPayload(payload) {
    if (!payload) {
        return [];
    }
    try {
        const json = JSON.parse(payload);
        if (Array.isArray(json.certificates)) {
            return json.certificates
                .map((item) => (typeof item === 'string' ? item.trim() : null))
                .map(fromBase64ToPem)
                .filter(Boolean);
        }
    } catch (error) {
        // treat as PEM bundle below
    }
    return payload
        .split(/\n(?=-----BEGIN CERTIFICATE-----)/g)
        .map((block) => block.trim())
        .filter((block) => block.length > 0);
}

function fromBase64ToPem(base64) {
    if (!base64) {
        return null;
    }
    const normalized = base64.replace(/\s+/g, '');
    const lines = normalized.match(/.{1,64}/g) || [normalized];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}

async function fetchText(url) {
    const { body } = await httpRequest(url);
    return body;
}

async function fetchJson(url) {
    const { body } = await httpRequest(url);
    return JSON.parse(body);
}

function httpRequest(url) {
    return new Promise((resolve, reject) => {
        const request = https.get(url, {
            headers: {
                'User-Agent': 'dariaAttest/1.0'
            }
        }, (response) => {
            const { statusCode } = response;
            const chunks = [];
            response.on('data', (chunk) => chunks.push(chunk));
            response.on('end', () => {
                const body = Buffer.concat(chunks).toString('utf8');
                if (statusCode && statusCode >= 200 && statusCode < 300) {
                    resolve({ body, statusCode });
                } else {
                    reject(new Error(`Failed to fetch ${url}: ${statusCode}`));
                }
            });
        });

        request.on('error', reject);
        request.end();
    });
}

module.exports = bootstrapServices;
