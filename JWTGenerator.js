const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const ErrorWeb = require('./ErrorWeb');

class JWTGenerator {
    constructor() {
        this.Secret = crypto.randomBytes(32).toString('hex');
    }

    generateToken(payload, options = {}) {
        const defaultOptions = {
            expiresIn: '1h',
            issuer: 'laboratorio8-api'
        };
        return jwt.sign(payload, this.Secret, { ...defaultOptions, ...options });
    }

    verifyToken(token, options) {
        try {
            return jwt.verify(token, this.Secret, options);
        } catch (err) {
            throw new ErrorWeb('Token inválido o expirado', 401);
        }
    }

    decodeToken(token) {
        return jwt.decode(token);
    }
}

module.exports = JWTGenerator;

