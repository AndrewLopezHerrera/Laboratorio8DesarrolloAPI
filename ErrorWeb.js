class ErrorWeb extends Error {
    constructor(message, statusCode, details = {}) {
        super(message);
        this.statusCode = statusCode;
        this.details = details;
    }
}

module.exports = ErrorWeb;
