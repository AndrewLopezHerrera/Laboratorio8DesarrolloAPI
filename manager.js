import datos from './data/data.json' assert { type: 'json' };

class Manager {
    constructor() {
        this.users = datos.Usuarios;
        this.products = datos.Productos;
    }

    loadData() {
        this.users = datos.Usuarios;
        this.products = datos.Productos;
    }

    authenticate(username, password, secret) {
        this.loadData();
        const user = this.users.find(u => u.email === username && u.contrasena === password);
        if (!user) throw new Error('Invalid credentials');
        const token = jwt.sign({ sub: user.id }, secret, { expiresIn: '1h' });
        return { user, token };
    }

    getProducts(page = 1, limit = 10) {
        this.loadData();
        const start = (page - 1) * limit;
        return {
            items: this.products.slice(start, start + limit),
            page,
            limit,
            total: this.products.length
        };
    }
}

module.exports = Manager;
