//* Renamed and added path to .env because it's hidden on a mac.
require("dotenv").config({ path: ".env" });

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

app.listen(process.env.PORT);
app.use(express.json());

const nowTime = () => {
    let d = new Date(Date.now());
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
};

console.log(nowTime() + " Server startup...");
console.log(nowTime() + " Server ready: listening on port " + process.env.PORT);

app.post("/jwt", async (req, res) => {
    // Pointless to hash, but what the heck!
    //const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const hashedPassword = await bcrypt.hash(process.env.PASSWORD, 10);

    const storedUser = {
        username: process.env.BDOCUSER,
        password: hashedPassword,
    };

    const user = {};
    // Check if user and password are passed via query parameters
    if (req.query.username != null) {
        //console.log("User passed as parameter: " + req.query.username);
        user.username = req.query.username;
        user.password = req.query.password;
    } else {
        //console.log("User passed in body: " + req.body.username);
        user.username = req.body.username;
        user.password = req.body.password;
    }

    if (user.username != process.env.BDOCUSER) {
        console.log("Unknown user");
        return res.status(400).send({ error: "Unknown user" });
    }

    try {
        if (await bcrypt.compare(user.password, storedUser.password)) {
            let payload = {
                iss: process.env.ISSUER,
                aud: process.env.AUDIENCE,
                BdocModules: ["BDOC_INTERACTIVE", "BDOC_PRODUCTION"],
                UserName: user.username,
                Groups: ["GRP1", "GRP2"],
            };

            let options = {
                expiresIn: process.env.EXPIRESIN,
            };

            // Create JWT
            const accessToken = await jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, options);
            res.json({ accessToken: accessToken });

            // Decode JWT in order to determine exp date
            const { exp } = jwt.decode(accessToken);
            let expiresOn = new Date(exp * 1000);

            console.log(nowTime() + " Generated JWT");
            console.log("Access Token: " + accessToken);
            console.log(`Token expires on: ${expiresOn.toLocaleDateString()} ${expiresOn.toLocaleTimeString()}`);
            console.log(`\n${nowTime()} Server ready: listening on port ${process.env.PORT}`);
        } else {
            res.send({ error: "Wrong password" });
        }
    } catch {
        res.status(500).send();
    }
});
