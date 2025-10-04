// index.js — Endpoints completos 
require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const { v4: uuid } = require('uuid');
const fs = require('fs').promises;
const path = require('path');

const APIKeyGenerator = require('./APIKeyGenerator');
const JWTGenerator = require('./JWTGenerator');
const ErrorWeb = require('./ErrorWeb');

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// ===== Instancias =====
const apiKeyGen = new APIKeyGenerator();
const jwtGen = new JWTGenerator();

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

// ===== Middlewares =====
function requireApiKey(req, res, next) {
  try {
    const key = req.header('x-api-key');
    apiKeyGen.validateAPIKey(key); // lanza ErrorWeb si no coincide
    next();
  } catch (err) { next(err); }
}

function authJWT(req, res, next) {
  const auth = req.header('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return next(new ErrorWeb('Falta token', 401));
  try {
    req.user = jwtGen.verifyToken(token);
    next();
  } catch (err) { next(err); }
}

const roleCheck = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return next(new ErrorWeb('Permisos insuficientes', 403));
  }
  next();
};

// ===== Datos de demo en memoria  =====
import users from './users.json' assert { type: 'json' };

import products from './products.json' assert { type: 'json' };

// ===== Funciones para persistir datos =====
async function saveToJSON(filename, data) {
  try {
    const filePath = path.join(__dirname, filename);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
    console.log(`Datos guardados en ${filename}`);
  } catch (error) {
    console.error(`Error guardando ${filename}:`, error.message);
    throw new ErrorWeb(`Error guardando datos: ${error.message}`, 500);
  }
}

async function saveProducts() {
  return saveToJSON('products.json', products);
}

async function saveUsers() {
  return saveToJSON('users.json', users);
}

// ===== Endpoints =====
app.get('/', (req, res) => {
  res.type('text/html').send(`<h1>Laboratorio 8 API</h1>
  <p>Servidor operativo</p>

  <ul>
    <li>GET /ping</li>
    <li>POST /auth/login (x-api-key)</li>
    <li>GET /products (x-api-key)</li>
    <li>GET /products/:id (x-api-key)</li>
    <li>POST /products (Bearer JWT, role editor/admin)</li>
    <li>PUT /products/:id (Bearer JWT, role editor/admin)</li>
    <li>DELETE /products/:id (Bearer JWT, role admin)</li>
  </ul>`);
});

app.get('/ping', (req, res) => res.status(200).json(ok(req, { pong: true })));

// --- Auth ---
app.post('/auth/login', requireApiKey, (req, res, next) => {
  try {
    const { username, password, secret } = req.body || {};
    if (!username || !password || !secret) {
      return res.status(400).json(fail(req, 400, 'BAD_REQUEST', 'username, password and secret required'));
    }
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
      return res.status(401).json(fail(req, 401, 'UNAUTHORIZED', 'Invalid credentials'));
    }
    const token = jwtGen.generateToken(
      { sub: user.id, role: user.role, username: user.username },
      { expiresIn: process.env.JWT_EXPIRES || '2h' }
    );
    res.status(200).json(ok(req, { token }));
  } catch (err) { next(err); }
});

// --- Products ---
// Listar con paginación
app.get('/products', requireApiKey, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit = Math.max(1, parseInt(req.query.limit || '10', 10));
  const offset = (page - 1) * limit;
  const items = products.slice(offset, offset + limit);
  res.status(200).json(ok(req, items, { page, limit, total: products.length }));
});

// Detalle por id
app.get('/products/:id', requireApiKey, (req, res) => {
  const prod = products.find(p => p.id === req.params.id);
  if (!prod) return res.status(404).json(fail(req, 404, 'NOT_FOUND', 'Product not found'));
  res.status(200).json(ok(req, prod));
});

// Crear
app.post('/products', authJWT, roleCheck('editor', 'admin'), async (req, res, next) => {
  try {
    const b = req.body || {};
    const errors = validateProduct(b);
    if (errors.length) return res.status(422).json(fail(req, 422, 'UNPROCESSABLE_ENTITY', 'Invalid data', errors));
    if (products.some(p => p.sku === b.sku)) return res.status(409).json(fail(req, 409, 'CONFLICT', 'SKU already exists'));
    
    const entity = { 
      id: uuid(), 
      name: b.name, 
      sku: b.sku, 
      price: Number(b.price), 
      stock: Number(b.stock), 
      category: b.category 
    };
    
    products.push(entity);
    await saveProducts();
    
    res.status(201).json(ok(req, entity));
  } catch (err) { 
    next(err); 
  }
});

// Actualizar
app.put('/products/:id', authJWT, roleCheck('editor', 'admin'), async (req, res, next) => {
  try {
    const idx = products.findIndex(p => p.id === req.params.id);
    if (idx === -1) return res.status(404).json(fail(req, 404, 'NOT_FOUND', 'Product not found'));
    
    const merged = { ...products[idx], ...req.body };
    const errors = validateProduct(merged);
    if (errors.length) return res.status(422).json(fail(req, 422, 'UNPROCESSABLE_ENTITY', 'Invalid data', errors));
    
    if (req.body?.sku && req.body.sku !== products[idx].sku && products.some(p => p.sku === req.body.sku)) {
      return res.status(409).json(fail(req, 409, 'CONFLICT', 'SKU already exists'));
    }
    
    products[idx] = { ...products[idx], ...{ 
      name: merged.name, 
      sku: merged.sku, 
      price: Number(merged.price), 
      stock: Number(merged.stock), 
      category: merged.category 
    }};
    
    await saveProducts();
    
    res.status(200).json(ok(req, products[idx]));
  } catch (err) { 
    next(err); 
  }
});

// Eliminar
app.delete('/products/:id', authJWT, roleCheck('admin'), async (req, res, next) => {
  try {
    const idx = products.findIndex(p => p.id === req.params.id);
    if (idx === -1) return res.status(404).json(fail(req, 404, 'NOT_FOUND', 'Product not found'));
    
    products.splice(idx, 1);
    await saveProducts();
    
    res.status(204).send();
  } catch (err) { 
    next(err); 
  }
});

// ===== Manejo de errores =====
app.use((err, req, res, next) => {
  const status = err?.statusCode || 500;
  const message = err?.message || 'Internal Server Error';
  const details = err?.details || undefined;
  res.status(status).json(fail(req, status, 'ERROR', message, details));
});

// ===== Arranque =====
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API running on http://localhost:${port}`));

// ===== Validación de producto =====
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
