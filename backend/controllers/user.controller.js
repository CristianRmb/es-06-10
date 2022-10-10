const User = require('../database/model/user.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

module.exports.signup = async (req, res) => {
  let email = req.body.email;
  let password = req.body.password;

  try {
    //* se la password è minore di 8 caratteri
    if (password.length < 8) {
      throw new Error('La password deve essere di almeno 8 caratteri');
    }

    //* controllo se esiste un untente con la mail passata nella post
    let user = await User.findOne({ email: email });
    if (user) {
      // se esiste
      throw new Error('Esiste gia utente con questa email');
    } else {
      password = await bcrypt.hash(password, 12);
      let userData = new User({ email: email, password: password });
      await userData.save();

      //rispondo al client con il messaggio di corretta iscrizione
      res.send({ status: 200, message: 'iscritto correttamente', body: {} });
    }
  } catch (error) {
    //qualunque eccezione risponde al client con il messaggio lanciato
    res.send({
      status: 400,
      message: error.message,
      body: {},
    });
  }

  // let userData = new User({ email: email, password: password });
  // await userData.save();
  // res.send('ok iscritto');
};

module.exports.login = async (req, res) => {
  let { email, password } = req.body;

  try {
    //Verifico che esista la mail
    let user = await User.findOne({ email: email });
    if (!user) {
      //Se non esiste rispondo con un errore
      throw new Error('Non esiste utete con questa email');
    } else {
      //se esiste, controllo che la password sia corretta
      let isCorrect = await bcrypt.compare(password, user.password);
      if (!isCorrect) {
        throw new Error('La password inserita non è corretta ');
      } else {
        const token = await jwt.sign(
          { email: user.email },
          process.env.SECRET_KEY,
          { expiresIn: '1d' },
        );
        res.send({
          status: 200,
          message: 'login effettuato correttamente',
          body: token,
        });
      }
    }
  } catch (error) {
    res.send({ status: 400, message: error.message, body: {} });
  }
};

module.exports.delete = async (req, res) => {
  let { email, password } = req.body;

  try {
    //! Verifico che esista utente con questa mail e password
    let user = await User.findOne({ email: email });
    if (!user) {
      //Se non esiste rispondo con un errore
      throw new Error('Non esiste utete con questa email');
    } else {
      //se esiste, controllo che la password sia corretta
      let isCorrect = await bcrypt.compare(password, user.password);
      if (!isCorrect) {
        throw new Error('La password inserita non è corretta ');
      } else {
        // .find va bene perche quando l'untente si rigistra si fa il controllo sulla mail
        // User.find({ email: email }).remove().exec();
        User.findByIdAndDelete({ _id: user._id }).exec();
        res.send({
          status: 200,
          message: 'utente eliminato correttamente',
        });
      }
    }
  } catch (error) {
    res.send({ status: 400, message: error.message, body: {} });
  }
};
