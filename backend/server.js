// per le variabili di sistema
const dotenv = require('dotenv');
const express = require('express');
const cors = require('cors');
const dbConnection = require('./database/connection');

dotenv.config();

const app = express();

app.use(cors()); // cross origin resource sharing
app.use(express.json());

app.use('/api/v1/user', require('./routes/user.route'));
// app.use('/api/v1/product', require('./routes/product.route'));

dbConnection();

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

