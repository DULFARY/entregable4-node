const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {email, password, firstName, lastName, country, image, frontBaseUrl} = req.body;
    const encriptedpassword = await bcrypt.hash(password,10);
    const result = await User.create({
        email,
        password: encriptedpassword,
        firstName,
        lastName,
        country,
        image,
    });
        //GENERA LINK MAS CODIGO 
    const code = require('crypto').randomBytes(32).toString('hex');// genera codigo link
    const link = `${frontBaseUrl}/${code}`; // link

    // GENERA REGISTRO
    await EmailCode.create({
        code: code,
        userId: result.id,

    });


      //ENVIO DE CORREO
    await sendEmail({
        to: email,
        subject:'verificacion de email de mi app',
        html:`
           <h1>hola ${firstName} ${lastName}</h1>
           <p>gracias por confiar en nuestra compañia</p>
           <p> para verificar tu email, haz clic en el siguente enlace</P>
           <a href="${link}">${link}</a>
        `
    });
    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const {email, firstName, lastName, country, image} = req.body
    const result = await User.update(
        {email, firstName, lastName, country, image},
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode = catchError(async(req, res) => {
    const {code} = req.params;
   const emailCode= await EmailCode.findOne({where: {code: code}})
   if (!emailCode) return res.status(401).json({message: 'invalido el codigo'});
  
   const user = await User.findByPk(emailCode.userId);
   user.isVerified = true;
   await user.save();

    //const user = await User.update(
    //   {isVerified: true},
    //  {where: emailCode.userId, returning: true},
   // );
   await emailCode.destroy();
   return res.json (user);

});
 //VALIDO EMAIL Y LA CONTRASEÑA
const login = catchError(async(req, res) => {
    const { email, password} = req.body; 
    const user = await User.findOne({where: {email: email}});
   if (!user) return res.status(401).json({message:'Invalid credentials'});
   if (!user.isVerified) return res.status(401).json({message:'user is not verified'});
   const isValid = await bcrypt.compare(password, user.password);// contra usuari y la incrit
   if (!isValid) return res.status(401).json({message:'Invalid credentials'});

  // GENERA EL TOKEN EN EL POSTMA
   const token = jwt.sign(
    {user},//parametros
    process.env.TOKEN_SECRET,//PARAMETRO CLAVE SECRETA VIENE .ENV
    {expiresIn:"1d"}// TIEMPO DEL TOKEN 

   )
    return res.json({ user, token });
});
// USURIO PROTEGIDOS
const getLoggedUser = catchError(async(req, res) => {
    const getLoggedUser = req.user;
    return res.json(getLoggedUser);
});


module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    login,
    getLoggedUser,
}