const express = require('express')
const speakeasy = require('speakeasy')
const qrcode = require('qrcode')
const sql = require("mssql");
const cors = require('cors')
const jwt = require('jsonwebtoken');
const app = express()

// Add the middleware to parse the request body
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

function verifyToken(req, res, next) {
  // Get the token from the Authorization header
  
  console.log(req.headers)
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token || token === null) {
    return res.status(403).send('No token provided.');
  }

  // Verify the token
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).send('Failed to authenticate token.');
    }

    // If token is valid, save user info to request object for use in other routes
    req.user = decoded;
    next(); // Continue to the next middleware or route handler
  });
}


// Connect to SQL Server
sql.connect(config, err => {
  if (err) {
      console.log(err);
      console.log("--------------------------------------------------------");
      console.log("--------------------------------------------------------");
      console.log("--------------------------------------------------------");
      console.log("--------------------------------------------------------");
  }
  else{console.log("Connection Successful!");} 

});



// Define route for fetching data from SQL Server
app.post("/getUserExistance", (request, response) => {

  const username = request.body.name
  const password = request.body.password
  
  if(!username){return response.status(401).send('Username Required') }

  new sql.Request().query(`SELECT * FROM dbo.P_Login where user_name='${username}' `, (err, result) => {
      
      if (err) { console.error("Error executing query:", err) } 
      
      if (!result) { return response.status(401).send('Invalid Username') }
      
      const token = jwt.sign({ username: username }, secretKey, { expiresIn: '1h' });

      response.json({ token });
    
  });
});




// Generate a QR code for 2FA and return a JWT along with it
app.post('/auth-qr', verifyToken, (req, res) => {
  const user = req.body.name;

  console.log(req.body);
  console.log(`name ${user}`);

  // Generate a secret for the user for 2FA
  const secret = speakeasy.generateSecret({
    name: user,
  });

  console.table(secret)

  // Store the secret temporarily for the user
  secrets.set(user, secret.base32);

  // Convert the secret into a QR code that the user can scan
  qrcode.toDataURL(secret.otpauth_url, (err, data) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error generating QR code');
    }

    // Create a payload for the JWT that includes the user's name and 2FA status
    const payload = {
      name: user,
      twoFactorAuthEnabled: false, // The user hasn't completed 2FA yet
    };

    // Generate a JWT token (valid for 10 minutes)
    const token = jwt.sign(payload, secretKey, { expiresIn: '10m' });

    // Send the QR code and the token back to the client
    res.json({
      qrCode: data,
      token,
    });
  });
});





app.post('/verify-token', verifyToken, (req, res) => {

  console.table(req.body)
  const { code, name } = req.body;
  const storedSecret = secrets.get(name);

  console.log(`Secret : ${storedSecret}`)
  
  const verified = speakeasy.totp.verify({
    secret: storedSecret,
    encoding: 'base32',
    token: code,
    window: 1,
  });

  if (verified) {
    res.json({ message: 'Authentication successful' });
  } else {
    res.status(401).json({ message: 'Authentication failed' });
  }
  
});



app.get('/', (req, res) => {
  res.send('Hello World!')
})



app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})