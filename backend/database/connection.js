const mongoose = require('mongoose');

module.exports = async () => {
  try {
    await mongoose.connect(process.env.DB_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Database connection established...');
  } catch (error) {
    console.log(`Unable to connect to mongodb Database: ${error}`);
  }
};
