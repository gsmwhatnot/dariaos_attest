const createApp = require('./app');
const {
    PORT,
    BASE_PATH
} = require('./config');
const buildRouter = require('./routes');
const bootstrapServices = require('./services');

async function main() {
    const services = await bootstrapServices();
    const app = createApp({ routes: () => buildRouter(services) });

    app.locals.services = services;

    app.listen(PORT, () => {
        const mountInfo = BASE_PATH || '/';
        // eslint-disable-next-line no-console
        console.log(`dariaAttest running on port ${PORT}, mounted at ${mountInfo}`);
    });
}

main().catch((error) => {
    // eslint-disable-next-line no-console
    console.error('Failed to start dariaAttest', error);
    process.exit(1);
});
