const express = require('express');
const { maskApiKey, formatAttestationDebug } = require('../core/attestation');

function buildVerifyRouter(services) {
    const router = express.Router();

    router.post('/verify', async (req, res) => {
        const start = Date.now();
        const ip = req.ip;
        const xff = req.get('x-forwarded-for') || null;

        const apiKey = req.body?.apiKey;
        const chainData = req.body?.data;
        const enforceApiKey = Boolean(services.config?.enforceApiKey);

        const finish = () => Date.now() - start;

        const defaultPolicy = {
            attestationTimeoutSeconds: services.config?.attestationTimeoutSeconds ?? 600
        };

        const buildEmptyDevice = () => ({
            model: '',
            serial: '',
            manufacturer: '',
            warrantyFlag: '',
            warrantyValid: ''
        });

        const buildPolicy = (policyOverride = {}) => ({
            attestationTimeoutSeconds: Number.isFinite(policyOverride.attestationTimeoutSeconds)
                ? policyOverride.attestationTimeoutSeconds
                : defaultPolicy.attestationTimeoutSeconds
        });

        const buildLogEnvelope = ({
            status,
            reason,
            apiKeyValue,
            apiLabel = '',
            device = buildEmptyDevice(),
            evaluationIssues = [],
            error = '',
            policy = defaultPolicy
        }) => ({
            event: 'verify',
            status,
            reason,
            api: {
                key: maskApiKey(apiKeyValue),
                label: apiLabel || ''
            },
            device,
            evaluationIssues: Array.isArray(evaluationIssues) ? evaluationIssues : [],
            error: error || '',
            ip: ip || '',
            xff: xff || '',
            processingMs: finish(),
            policy: buildPolicy(policy)
        });

        try {
            if (enforceApiKey && !apiKey) {
                await services.logger.access(buildLogEnvelope({
                    status: 403,
                    reason: 'Access denied',
                    apiKeyValue: apiKey
                }));
                return res.status(403).json({ reason: 'Access denied', errorcode: 403 });
            }

            let keyResult = { valid: true, label: '' };
            if (enforceApiKey) {
                keyResult = await services.apiKeys.verify(apiKey);
                if (!keyResult.valid) {
                    await services.logger.access(buildLogEnvelope({
                        status: 403,
                        reason: 'Access denied',
                        apiKeyValue: apiKey,
                        apiLabel: keyResult.label || ''
                    }));
                    return res.status(403).json({ reason: 'Access denied', errorcode: 403 });
                }
            }

            const attestationResult = await services.attestation.verify({
                chainData,
                apiKey,
                enableDebug: services.flags?.debugAttestation || req.query.debug === '1'
            });

            if (attestationResult.debug) {
                // eslint-disable-next-line no-console
                console.log(formatAttestationDebug(attestationResult.debug));
            }

            if (attestationResult.deviceLog) {
                await services.logger.deviceAttest(attestationResult.deviceLog);
            }

            const payload = {
                ...attestationResult.log,
                api: {
                    key: attestationResult.log.api.key,
                    label: keyResult.label || ''
                },
                device: attestationResult.log.device || buildEmptyDevice(),
                evaluationIssues: Array.isArray(attestationResult.log.evaluationIssues)
                    ? attestationResult.log.evaluationIssues
                    : [],
                error: attestationResult.log.error || '',
                ip: ip || '',
                xff: xff || '',
                processingMs: finish(),
                policy: buildPolicy(attestationResult.log.policy)
            };
            await services.logger.access(payload);

            return res
                .status(attestationResult.response.errorcode)
                .json(attestationResult.response);
        } catch (error) {
            const statusCode = error.statusCode || 500;
            const reason = statusCode === 400
                ? 'Bad Request'
                : statusCode === 503
                    ? 'Service Unavailable'
                    : statusCode >= 500
                        ? 'Internal error'
                        : 'Unauthorized';

            await services.logger.access(buildLogEnvelope({
                status: statusCode,
                reason,
                apiKeyValue: apiKey,
                evaluationIssues: [],
                apiLabel: '',
                error: error.message || ''
            }));

            return res.status(statusCode).json({ reason, errorcode: statusCode });
        }
    });

    return router;
}

module.exports = buildVerifyRouter;
