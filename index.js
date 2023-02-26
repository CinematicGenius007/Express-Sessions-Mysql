require('dotenv').config();

const express = require('express');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const { join } = require('path');
const mysql = require('mysql2/promise');
const session = require('express-session');
const MysqlStore = require('express-mysql-session')(session);
const cron = require('node-cron');

const app = express();

app.set('view engine', 'ejs');
app.set('views', 'views');

app.use(morgan('dev'));
app.use(express.static('public'));
app.use('/css', express.static(join(__dirname, '/node_modules/bootstrap/dist/css')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());


const sqlOptions = {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Database connection
const connectionPool = mysql.createPool(sqlOptions);

if (connectionPool) {
    console.log('Database connected');
} else {
    console.log('Database connection failed');
}


// Session store
const sessionStore = new MysqlStore({
    expiration: (24 * 60 * 60 * 1000),
    createDatabaseTable: true,
    schema: {
        tableName: 'sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    }
}, connectionPool);


// Expression session
const expressSession = session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        maxAge: (24 * 60 * 60 * 1000),
        sameSite: true,
        secure: false,
        name: 'session',
        httpOnly: true,
        path: '/'
    }
});


app.use(expressSession);


const createHash = (password) => {
    return password.split('').reverse().join('');
};

const compareHash = (password, hash) => {
    return createHash(password) === hash;
}


app.get('/', (req, res) => {
    if (req.session.user) {
        res.status(200).redirect('/home');
    } else {
        res.status(200).render('index');
    }
});

app.get('/login', (req, res) => {
    if (req.session.user) {
        res.status(200).redirect('/home');
    } else {
        res.status(200).render('login');
    }
});

app.post('/login', (req, res) => {
    const { username, password, maxAge } = req.body;
    
    if (username && password) {
        connectionPool.getConnection()
            .then((connection) => {
                connection.query('SELECT * FROM users WHERE username = ?', [username])
                    .then(([results]) => {
                        if (results.length > 0) {
                            const user = results[0];
                            if (compareHash(password, user.password)) {
                                req.session.cookie.originalMaxAge = maxAge * 1000 * 60;
                                req.session.user = user;
                                req.session.count = 0;
                                res.status(200).redirect('/home');
                            } else {
                                console.log('Wrong password');
                                res.status(200).render('login');
                            }
                        } else {
                            console.log('User not found');
                            res.status(200).render('login');
                        }

                        connection.release();
                    })
                    .catch((error) => {
                        console.log(error);
                        res.status(500).render('500', { url: req.url, err: error.message });
                        connection.release();
                    });
            })
            .catch((error) => {
                console.log(error);
                res.status(500).render('500', { url: req.url, err: error.message });
            });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.status(200).redirect('/login');
});

app.get('/register', (req, res) => {
    if (req.session.user) {
        res.status(200).redirect('/home');
    } else {
        res.status(200).render('register');
    }
});

app.post('/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;

    if (username && password && confirmPassword && password === confirmPassword) {
        connectionPool.getConnection()
            .then((connection) => {
                connection.query('SELECT * FROM users WHERE username = ?', [username])
                    .then(([results]) => {
                        if (results.length > 0) {
                            res.status(200).render('register');
                        } else {
                            connection.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, createHash(password)])
                                .then(() => {
                                    res.status(200).redirect('/login');
                                })
                                .catch((error) => {
                                    console.log(error);
                                    res.status(500).render('500', { url: req.url, err: error.message });
                                });
                        }

                        connection.release();
                    })
                    .catch((error) => {
                        console.log(error);
                        res.status(500).render('500', { url: req.url, err: error.message });
                        connection.release();
                    });
            })
            .catch((error) => {
                console.log(error);
                res.status(500).render('500', { url: req.url, err: error.message });
            });
    } else {
        res.status(200).render('register');
    }
});

app.get('/home', (req, res) => {
    if (req.session.user) {
        req.session.count++;
        res.status(200).render('home', { counter: req.session.count, maxAge: req.session.cookie.originalMaxAge / 1000 });
    } else {
        res.status(200).redirect('/login');
    }
});


// 404 error handler
app.use((req, res, _next) => {
    res.status(404).render('404', { url: req.url });
});

app.use((err, req, res, _next) => {
    console.error(err.stack);
    res.status(500).render('500', { url: req.url, err: err.message });
});


app.listen(process.env.PORT || 3000, () => {
    console.log(`Server is running on port ${process.env.PORT || 3000}`);
});


// Cron job for destroying expired sessions using sessionStore
cron.schedule('*/1 * * * *', () => {
    sessionStore.clearExpiredSessions((error) => {
        if (error) {
            console.log(error);
        }
    });
});