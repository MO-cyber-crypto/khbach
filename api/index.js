// Lightweight Vercel adapter to forward requests to the Express app

const { createApp } = require('../server');

let appPromise = null;

module.exports = async (req, res) => {
  if (!appPromise) {
    appPromise = createApp();
  }

  const app = await appPromise;

  // Express expects Node's http.IncomingMessage and http.ServerResponse — which Vercel provides to this function.
  // We can call app.handle(req, res) to let Express process the request.
  return app.handle(req, res);
};
