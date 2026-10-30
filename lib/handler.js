const { route } = require('./core');

module.exports = function handler(req, res) {
  Promise.resolve(route(req, res)).catch((e) => {
    try {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: (e && e.message) || 'server error' }));
    } catch (_) { /* ignore */ }
  });
};