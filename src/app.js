const express = require('express');
const {
    BASE_PATH,
    resolveAppPath,
    SITE_NAME
} = require('./config');

function createApp({ routes }) {
    const app = express();

    app.disable('x-powered-by');
    app.set('trust proxy', true);
    app.use(express.json({ limit: '1mb' }));

    if (routes && typeof routes === 'function') {
        const router = routes();
        const mountPath = BASE_PATH || '/';
        app.use(mountPath, router);
    }

    app.get(resolveAppPath('/health'), (req, res) => {
        res.json({ status: 'ok', site: SITE_NAME });
    });

    app.use((err, req, res, _next) => {
        if (err instanceof SyntaxError && 'body' in err) {
            return res.status(400).json({ reason: 'Bad Request', errorcode: 400 });
        }
        // eslint-disable-next-line no-console
        console.error('Unhandled error', err);
        return res.status(500).json({ reason: 'Internal server error', errorcode: 500 });
    });

    return app;
}

module.exports = createApp;
