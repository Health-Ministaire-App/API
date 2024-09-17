const express = require('express')
const speakeasy = require('speakeasy')
const qrcode = require('qrcode')
const sql = require("mssql");
const cors = require('cors')
const jwt = require('jsonwebtoken');

const app = express()

app.use(express.json())

require('dotenv').config();
const secretKey = process.env.SECRET_KEY;


// SQL Server configuration
const config = {
  user: "ilyass",                      // Database username
  password: "isba",                    // Database password
  server: "DESKTOP-8HVJV89",           // Use the server name
  database: "DB_Global_Hearts",        // Database name
  options: {
    encrypt: true,                      // Enable encryption
    trustServerCertificate: true        // Trust the server certificate
  }
};

let corsOptions = {
  origin : ['http://localhost:4200'],
}


app.use(cors(corsOptions))

const port = 3000

const secrets = new Map();  


sql.connect(config, err => {
  if (err) {
      console.log(err);
  }
  else{console.log("Connection Successful!");} 

});


function verifyToken(req, res, next) {
  
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token || token === null) {
    return res.status(403).send('No token provided.');
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).send('Failed to authenticate token.');
    }

    req.user = decoded;
    next();
  });
}

function changeUserVariablesinDB(col, user, value, ifString){

  const query = (ifString) 
  ? `UPDATE dbo.P_Login SET ${col} = '${value}' WHERE user_name='${user}'`
  : `UPDATE dbo.P_Login SET ${col} = ${value} WHERE user_name='${user}'`;

  new sql.Request().query(query, (err, result) => {
    if (err) { console.error("Error executing query:", err) } 
  });

}


app.post("/getUserExistance", (request, response) => {

  const username = request.body.name
  // const password = request.body.password
  // const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
  
  if(!username){ return response.status(401).send('Username Required') }


  // new sql.Request().query(`SELECT * FROM dbo.P_Login where user_name='${username}' and password = ${hashedPassword}`, (err, result) => {
  new sql.Request().query(`SELECT * FROM dbo.P_Login where user_name='${username}'`, (err, result) => {
      
      if (err) { console.error("Error executing query:", err) } 
      
      if (result.recordset.length === 0) { return response.status(401).send('Invalid Username') }
      

      const token = jwt.sign({ username: username }, secretKey, { expiresIn: '1h' });

      changeUserVariablesinDB('token', username, token, true)

      // const resultRes = result.recordset;
      // response.json({ token , resultRes });
      response.json({ token });
    
  });
});




app.post('/auth-qr', verifyToken, (req, res) => {
  const user = req.body.name;

  const secret = speakeasy.generateSecret({
    name: user,
  });
  
  changeUserVariablesinDB('mfa_secret_key', user, `CONVERT(VARBINARY, '${secret.base32}')`, false)

  secrets.set(user, secret.base32);

  qrcode.toDataURL(secret.otpauth_url, (err, data) => {

    if (err) {
      console.error(err);
      return res.status(500).send('Error generating QR code');
    }

    const payload = {
      name: user,
      twoFactorAuthEnabled: false,
    };

    const token = jwt.sign(payload, secretKey, { expiresIn: '10m' });

    res.json({
      qrCode: data,
      token,
    });
  });
});





app.post('/verify-token', verifyToken, (req, res) => {

  const { code, name } = req.body;
  const storedSecret = secrets.get(name);
  
  const verified = speakeasy.totp.verify({
    secret: storedSecret,
    encoding: 'base32',
    token: code,
    window: 1,
  });

  if (verified) {
    
    changeUserVariablesinDB('actif', user, 1, false)

    changeUserVariablesinDB('loged', user, 1, false)

    res.json({ message: 'Authentication successful' });

  } else {res.status(401).json({ message: 'Authentication failed' });}
  
});



app.get('/', (req, res) => {
  res.send('Hello World!')
})



app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})