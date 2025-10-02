class Middleware {
    constructor() {
        
    }

    generateErrorBody(code, message, details = {}, timestamp = new Date().toISOString(), path = '') {
        return {
            error: {
                code,
                message,
                details,
                timestamp,
                path
            }
        };
    }
}

module.exports = Middleware;