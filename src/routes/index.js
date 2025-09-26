const path = require('path');
const express = require('express');
const verifyRouter = require('../api/verify');
const buildAdminRouter = require('../admin/router');

function buildRouter(services) {
    const router = express.Router();

    router.get('/', (_req, res) => {
        res.json({ message: 'dariaAttest ready' });
    });

    router.use('/api/v1', verifyRouter(services));

    router.use('/admin', buildAdminRouter(services));

    const staticDir = path.join(__dirname, '..', 'web', 'public');
    router.use('/admin', express.static(staticDir));
    router.get('/admin*', (_req, res) => {
        res.sendFile(path.join(staticDir, 'index.html'));
    });

    return router;
}

module.exports = buildRouter;
