//* Renamed and added path to .env because it's hidden on a mac.
require('dotenv').config({ path: 'jwt.env' });

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

app.listen(2000);
app.use(express.json());

const nowTime = () => {
    let d = new Date(Date.now());
    return (`${d.toLocaleDateString()} ${d.toLocaleTimeString()}`);
};

console.log(nowTime() + " Server startup...");
console.log(nowTime() + " Server ready: listening on port 2000.");
console.log(process.env.AUDIENCE);



app.post("/jwt", async (req, res) => {

    // Pointless to hash, but what the heck!
    //const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const hashedPassword = await bcrypt.hash(process.env.PASSWORD, 10);

    const user = {
        user: req.body.user,
        password: hashedPassword,
    };

    console.log(process.env.USERNAME);

    if ((user.user != process.env.USERNAME)) {
        console.log("Unknown user");
        return res.status(400).send({error: "Unknown user"});
    }

    try {
        if (await bcrypt.compare(req.body.password, user.password)) {

            let payload = {
                iss: process.env.ISSUER,
                aud: process.env.AUDIENCE,
                "BdocModules": [
                    "BDOC_INTERACTIVE",
                    "BDOC_PRODUCTION"
                ],
                "UserName": user.user,
                "Groups": [
                    "GRP1",
                    "GRP2"
                ]
            };

            let options = {
                expiresIn: process.env.EXPIRESIN
            };

            // Create JWT
            const accessToken = await jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, options);
            res.json({accessToken: accessToken});
            console.log(nowTime() + " Generated JWT");
        } else {
            res.send({error: "Wrong password"});
        }
    } catch {
        res.status(500).send();
    }
});

