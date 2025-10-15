// Lightweight Vercel adapter to forward requests to the Express app

const { createApp } = require('../server');

let appPromise = null;

module.exports = async (req, res) => {
  try {
    if (!appPromise) {
      appPromise = createApp();
    }

    const app = await appPromise;

    // Express expects Node's http.IncomingMessage and http.ServerResponse — which Vercel provides to this function.
    // We can call app.handle(req, res) to let Express process the request.
    return app.handle(req, res);
  } catch (err) {
    // Initialization failed (likely missing env or DB cannot connect). Return a controlled response.
    console.error('Initialization error in serverless adapter:', err && err.message ? err.message : err);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({
      error: 'Server initialization failed',
      message: err && err.message ? err.message : 'Unknown error'
    }));
  }
};
