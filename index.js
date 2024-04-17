import express from "express";
import cors from "cors";
import axios from "axios";

import { Agent } from "https";

const app = express()
app.use(cors())
app.use(express.json())

// Custom_Error_Class_for_Auth_ Errors

class ValReauthScriptError extends Error {

    constructor(message) {
        super(message);
        this.name = "ValReauthScriptError";
    }
}

// ciphers_to_bypass_hcaptcha -- required_for_fetching_accessToken

const ciphers = [
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
];

const agent = new Agent({
    ciphers: ciphers.join(':'),
    honorCipherOrder: true,
    minVersion: "TLSv1.2"
});

// parseURL_to_get_AccessToken

const parseUrl = (uri) => {
    const loginResponseURI = new URL(uri);
    const accessToken = loginResponseURI.searchParams.get('access_token');
    const idToken = loginResponseURI.searchParams.get('id_token')
    const expiresIn = parseInt(
        loginResponseURI.searchParams.get('expires_in'));

    return { accessToken, idToken, expiresIn };
}

// Get Riot client version

const getUserAgent = () => axios({
    method: "GET",
    url: "https://valorant-api.com/v1/version",
})

const getClientVersion = async () => {
    const data = await getUserAgent()
    return data.data
}

app.get("/client", async (req, res) => {

    getClientVersion()
        .then(data => {
            res.send(data)
        })
        .catch(error => {
            console.error("Error fetching data:", error.message)
            res.send({ Error: { name: error.name, message: error.message } })
        })
})

// Prepare_cookies_for_the_auth_request -- POST Auth Cookies

const createSession = (client = "82.0.1.1194.2870") => axios({
    method: "POST",
    url: "https://auth.riotgames.com/api/v1/authorization",
    headers: {
        "User-Agent": `RiotClient/${client} rso-auth (Windows; 10;;Professional, x64)`
    },
    data: {
        client_id: "play-valorant-web-prod",
        nonce: "1",
        redirect_uri: "https://playvalorant.com/opt_in",
        response_type: "token id_token",
        response_mode: "query",
        scope: "account openid"
    },
    httpsAgent: agent
})

// Perform_authorization_request_to_get_token -- PUT Auth Request
// Requires_cookies_from_the_Auth_Cookies_stage. The_token_can_be_found_in_the_uri_property.

const login = (cookie, username, password, client = "82.0.1.1194.2870") => axios({
    method: "PUT",
    url: "https://auth.riotgames.com/api/v1/authorization",
    headers: {
        Cookie: cookie,
        "User-Agent": `RiotClient/${client} rso-auth (Windows; 10;;Professional, x64)`
    },
    data: {
        type: "auth",
        username,
        password
    },
    httpsAgent: agent
});

const auth = async (client = "82.0.1.1194.2870", username, password) => {

    const session = await createSession(client)

    let asidCookie = session.headers["set-cookie"].find(cookie => /^asid/.test(cookie));
    console.log("Cookies:", asidCookie)

    const loginResponse = await login(asidCookie, username, password)

    return loginResponse
}

app.post("/auth", async (req, res) => {

    const data = req.body

    const client = data.client
    const username = data.username
    const password = data.password

    console.log(data)

    auth(client, username, password)
        .then(resp => {

            if (typeof resp.data.error !== "undefined") {
                // console.dir(resp.data)
                if (resp.data.error === "auth_failure")
                    throw new ValReauthScriptError("Invalid Login Credentials");
                throw new ValReauthScriptError("Unknown Error");
            }

            let tokens = parseUrl(resp.data.response.parameters.uri)
            res.send(tokens)
        })
        .catch(error => {
            console.error("Error fetching data:", error.message)
            res.send({ Error: { name: error.name, message: error.message } })
        })
})

app.listen(8080, () => {
    console.log("CORS-enabled web server listening on port 8080")
})