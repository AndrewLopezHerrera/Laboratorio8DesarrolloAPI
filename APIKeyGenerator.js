const crypto = require('crypto');
const ErrorWeb = require('./ErrorWeb');

class APIKeyGenerator {
    constructor() {
        this.apiKey = crypto.randomBytes(32).toString('hex');
    }

    getAPIKey() {
        return this.apiKey;
    }

    validateAPIKey(key) {
        if(key === this.apiKey) {
            return true;
        }
        throw new ErrorWeb('API Key inválida', 403);
    }
}

module.exports = APIKeyGenerator;