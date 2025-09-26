const express = require('express');
const { maskApiKey } = require('../core/attestation');

function buildAdminRouter(services) {
    const router = express.Router();

    router.post('/api/login', async (req, res) => {
        const { password } = req.body || {};
        const ip = req.ip;
        const xff = req.get('x-forwarded-for') || null;

        if (!password) {
            return res.status(400).json({ error: 'Password required' });
        }
        try {
            const result = await services.admin.verifyPassword(password);
            if (!result.success) {
                await services.logger.audit({
                    event: 'admin-login-failed',
                    api: { key: '', label: '' },
                    ip: ip || '',
                    xff: xff || '',
                    detail: ''
                });
                return res.status(403).json({ error: 'Invalid credentials' });
            }
            const session = await services.admin.createSession();
            await services.logger.audit({
                event: 'admin-login',
                api: { key: '', label: '' },
                ip: ip || '',
                xff: xff || '',
                detail: ''
            });
            return res.json({
                token: session.token,
                expiresAt: session.expiresAt,
                mustChangePassword: result.mustChangePassword
            });
        } catch (error) {
            return res.status(500).json({ error: 'Internal error' });
        }
    });

    router.post('/api/logout', async (req, res) => {
        const token = extractToken(req);
        const ip = req.ip;
        const xff = req.get('x-forwarded-for') || null;
        if (!token) {
            return res.status(400).json({ error: 'Missing token' });
        }
        await services.admin.revokeSession(token);
        await services.logger.audit({
            event: 'admin-logout',
            api: { key: '', label: '' },
            ip: ip || '',
            xff: xff || '',
            detail: ''
        });
        return res.json({ success: true });
    });

    router.post('/api/password', async (req, res) => {
        const session = await requireSession(req, res, services, { allowDuringMustChange: true });
        if (!session) {
            return null;
        }
        const { currentPassword, newPassword } = req.body || {};
        if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters' });
        }
        const check = await services.admin.verifyPassword(currentPassword || '');
        if (!check.success) {
            return res.status(403).json({ error: 'Invalid current password' });
        }
        await services.admin.updatePassword(newPassword);
        await services.logger.audit({
            event: 'admin-password-changed',
            api: { key: '', label: '' },
            ip: req.ip || '',
            xff: req.get('x-forwarded-for') || '',
            detail: ''
        });
        return res.json({ success: true });
    });

    router.get('/api/profile', async (req, res) => {
        const session = await requireSession(req, res, services, { allowDuringMustChange: true });
        if (!session) {
            return null;
        }
        const state = await services.admin.state();
        return res.json({
            site: services.config.SITE_NAME,
            mustChangePassword: state.mustChangePassword,
            session: {
                expiresAt: session.expiresAt
            }
        });
    });

    router.get('/api/keys', async (req, res) => {
        const session = await requireSession(req, res, services);
        if (!session) {
            return null;
        }
        const keys = await services.apiKeys.list();
        return res.json({ keys });
    });

    router.post('/api/keys', async (req, res) => {
        const session = await requireSession(req, res, services);
        if (!session) {
            return null;
        }
        const { label } = req.body || {};
        if (!label || typeof label !== 'string') {
            return res.status(400).json({ error: 'Label required' });
        }
        try {
            const result = await services.apiKeys.create(label);
            await services.logger.audit({
                event: 'apikey-created',
                api: {
                    key: maskApiKey(result.apiKey),
                    label: label || ''
                },
                ip: req.ip || '',
                xff: req.get('x-forwarded-for') || '',
                detail: ''
            });
            return res.status(201).json(result);
        } catch (error) {
            if (error && error.code === 'LABEL_EXISTS') {
                return res.status(409).json({ error: 'Label already exists' });
            }
            if (error && error.code === 'LABEL_REQUIRED') {
                return res.status(400).json({ error: 'Label required' });
            }
            return res.status(500).json({ error: 'Internal error' });
        }
    });

    router.patch('/api/keys/:id', async (req, res) => {
        const session = await requireSession(req, res, services);
        if (!session) {
            return null;
        }
        const { id } = req.params;
        const { disabled } = req.body || {};
        if (typeof disabled !== 'boolean') {
            return res.status(400).json({ error: 'disabled flag required' });
        }
        const updated = await services.apiKeys.setDisabled(id, disabled);
        if (!updated) {
            return res.status(404).json({ error: 'Not found' });
        }
        await services.logger.audit({
            event: disabled ? 'apikey-disabled' : 'apikey-enabled',
            api: { key: '', label: updated.label || '' },
            keyId: id,
            ip: req.ip || '',
            xff: req.get('x-forwarded-for') || '',
            detail: ''
        });
        return res.json({ key: updated });
    });

    router.delete('/api/keys/:id', async (req, res) => {
        const session = await requireSession(req, res, services);
        if (!session) {
            return null;
        }
        const { id } = req.params;
        const { label } = req.body || {};
        try {
            const removed = await services.apiKeys.remove(id, label);
            if (!removed) {
                return res.status(404).json({ error: 'Not found' });
            }
            await services.logger.audit({
                event: 'apikey-deleted',
                api: { key: '', label: label || '' },
                keyId: id,
                ip: req.ip || '',
                xff: req.get('x-forwarded-for') || '',
                detail: ''
            });
            return res.json({ success: true });
        } catch (error) {
            if (error && error.code === 'LABEL_REQUIRED') {
                return res.status(400).json({ error: 'Label required' });
            }
            if (error && error.code === 'LABEL_MISMATCH') {
                return res.status(403).json({ error: 'Label mismatch' });
            }
            return res.status(500).json({ error: 'Internal error' });
        }
    });

    return router;
}

function extractToken(req) {
    const auth = req.get('authorization');
    if (auth && auth.toLowerCase().startsWith('bearer ')) {
        return auth.slice(7).trim();
    }
    const headerToken = req.get('x-admin-token');
    if (headerToken) {
        return headerToken.trim();
    }
    return null;
}

async function requireSession(req, res, services, options = {}) {
    const token = extractToken(req);
    if (!token) {
        res.status(401).json({ error: 'Unauthorized' });
        return null;
    }
    const session = await services.admin.validateSession(token);
    if (!session) {
        res.status(401).json({ error: 'Unauthorized' });
        return null;
    }
    const state = await services.admin.state();
    if (state.mustChangePassword && !options.allowDuringMustChange) {
        res.status(423).json({ error: 'Password change required' });
        return null;
    }
    req.admin = { token, state };
    return session;
}

module.exports = buildAdminRouter;
