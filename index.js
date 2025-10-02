// index.js (CommonJS, usando tus módulos tal cual)
require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');

const APIKeyGenerator = require('./APIKeyGenerator');     // :contentReference[oaicite:3]{index=3}
const JWTGenerator = require('./JWTGenerator');           // :contentReference[oaicite:4]{index=4}
const ErrorWeb = require('./ErrorWeb');                   // :contentReference[oaicite:5]{index=5}
const { v4: uuid } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// ===== Instancias de utilidades (se mantienen en memoria mientras esté vivo el proceso) =====
const apiKeyGen = new APIKeyGenerator();   // genera una API Key aleatoria al iniciar
const jwtGen = new JWTGenerator();         // genera un secreto aleatorio al iniciar

console.log('=========================================');
console.log(' API KEY para pruebas (x-api-key):');
console.log(`   ${apiKeyGen.getAPIKey()}`);
console.log('=========================================');

// ===== Helpers de respuesta uniforme =====
const ok = (req, data, meta = {}) => ({
  timestamp: new Date().toISOString(),
  path: req.originalUrl,
  success: true,
  data,
  meta
});
const fail = (req, status, code, message, details = []) => ({
  timestamp: new Date().toISOString(),
  path: req.originalUrl,
  success: false,
  error: { status, code, message, details }
});

// ===== Middlewares que envuelven tus clases =====
function requireApiKey(req, res, next) {
  try {
    const key = req.header('x-api-key');
    apiKeyGen.validateAPIKey(key); // lanza ErrorWeb(403) si no coincide  :contentReference[oaicite:6]{index=6}
    next();
  } catch (err) {
    next(err);
  }
}

function authJWT(req, res, next) {
  const auth = req.header('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return next(new ErrorWeb('Falta token', 401));
  try {
    req.user = jwtGen.verifyToken(token); // lanza ErrorWeb(401) si inválido/expirado  :contentReference[oaicite:7]{index=7}
    next();
  } catch (err) {
    next(err);
  }
}

const roleCheck = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return next(new ErrorWeb('Permisos insuficientes', 403));
  }
  next();
};

// ===== Datos de demo =====
const users = [
  { id: 'u1', username: 'alice', password: 'alice123', role: 'admin' },
  { id: 'u2', username: 'bob',   password: 'bob123',   role: 'editor' }
];

let products = [
  { id: uuid(), name: 'Laptop X', sku: 'SKU-0001', price: 999.99, stock: 5, category: 'computers' }
];

// ===== Rutas =====
app.get('/', (req, res) => {
  res.send(`<h1>Laboratorio 8 API</h1>
  <p>Servidor operativo listo</p>
  <ul>
    <li>GET <code>/ping</code></li>
    <li>POST <code>/auth/login</code> (header <code>x-api-key</code>)</li>
    <li>GET <code>/products</code> (header <code>x-api-key</code>)</li>
    <li>POST/PUT/DELETE <code>/products</code> (JWT + rol)</li>
  </ul>`);
});

app.get('/ping', (req, res) => res.json(ok(req, { ok: true })));

// Login: requiere API Key (usa tu generador para firmar token)
app.post('/auth/login', requireApiKey, (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json(fail(req, 400, 'BAD_REQUEST', 'username and password required'));
    }
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
      return res.status(401).json(fail(req, 401, 'UNAUTHORIZED', 'Invalid credentials'));
    }
    const token = jwtGen.generateToken(
      { sub: user.id, role: user.role, username: user.username }, // :contentReference[oaicite:8]{index=8}
      { expiresIn: process.env.JWT_EXPIRES || '2h' }
    );
    res.status(200).json(ok(req, { token }));
  } catch (err) { next(err); }
});

// Listar productos (API Key)
app.get('/products', requireApiKey, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit = Math.max(1, parseInt(req.query.limit || '10', 10));
  const start = (page - 1) * limit;
  const items = products.slice(start, start + limit);
  res.status(200).json(ok(req, items, { page, limit, total: products.length }));
});

// Detalle (API Key)
app.get('/products/:id', requireApiKey, (req, res) => {
  const prod = products.find(p => p.id === req.params.id);
  if (!prod) return res.status(404).json(fail(req, 404, 'NOT_FOUND', 'Product not found'));
  res.status(200).json(ok(req, prod));
});

// Crear (JWT + role editor/admin)
app.post('/products', authJWT, roleCheck('editor', 'admin'), (req, res) => {
  const b = req.body || {};
  const errors = validateProduct(b);
  if (errors.length) return res.status(422).json(fail(req, 422, 'UNPROCESSABLE_ENTITY', 'Invalid data', errors));
  if (products.some(p => p.sku === b.sku)) return res.status(409).json(fail(req, 409, 'CONFLICT', 'SKU already exists'));
  const entity = { id: uuid(), name: b.name, sku: b.sku, price: Number(b.price), stock: Number(b.stock), category: b.category };
  products.push(entity);
  res.status(201).json(ok(req, entity));
});

// Actualizar (JWT + role editor/admin)
app.put('/products/:id', authJWT, roleCheck('editor', 'admin'), (req, res) => {
  const idx = products.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json(fail(req, 404, 'NOT_FOUND', 'Product not found'));
  const merged = { ...products[idx], ...req.body };
  const errors = validateProduct(merged);
  if (errors.length) return res.status(422).json(fail(req, 422, 'UNPROCESSABLE_ENTITY', 'Invalid data', errors));
  if (req.body?.sku && req.body.sku !== products[idx].sku && products.some(p => p.sku === req.body.sku)) {
    return res.status(409).json(fail(req, 409, 'CONFLICT', 'SKU already exists'));
  }
  merged.price = Number(merged.price);
  merged.stock = Number(merged.stock);
  products[idx] = merged;
  res.status(200).json(ok(req, products[idx]));
});

// Eliminar (JWT + role admin)
app.delete('/products/:id', authJWT, roleCheck('admin'), (req, res) => {
  const before = products.length;
  products = products.filter(p => p.id !== req.params.id);
  if (products.length === before) return res.status(404).json(fail(req, 404, 'NOT_FOUND', 'Product not found'));
  res.status(204).send();
});

// 404 y manejador de errores (usando tu ErrorWeb.statusCode)
app.use((req, res) => res.status(404).json(fail(req, 404, 'NOT_FOUND', 'Route not found')));
app.use((err, req, res, _next) => {
  const status = err.statusCode || 500;             // :contentReference[oaicite:9]{index=9}
  const code = status === 401 ? 'UNAUTHORIZED'
            : status === 403 ? 'FORBIDDEN'
            : status === 404 ? 'NOT_FOUND'
            : 'INTERNAL_ERROR';
  res.status(status).json(fail(req, status, code, err.message || 'Internal Server Error'));
});

// Arrancar
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API running on http://localhost:${port}`));

// ---- validación local ----
function validateProduct(payload) {
  const errors = [];
  if (!payload || typeof payload !== 'object') errors.push({ field: 'body', msg: 'Invalid body' });
  if (!payload.name) errors.push({ field: 'name', msg: 'Required' });
  if (!payload.sku) errors.push({ field: 'sku', msg: 'Required' });
  if (!(Number(payload.price) > 0)) errors.push({ field: 'price', msg: 'Must be > 0' });
  if (!(Number.isInteger(Number(payload.stock)) && Number(payload.stock) >= 0))
    errors.push({ field: 'stock', msg: 'Must be integer >= 0' });
  if (!payload.category) errors.push({ field: 'category', msg: 'Required' });
  return errors;
}
