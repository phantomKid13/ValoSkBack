import express from "express";
import cors from "cors";
import axios from "axios";

import { Agent } from "https";

// Custom Error Class for Auth Errors

class ValReauthScriptError extends Error {
    data;
    constructor(message, data) {
        super(message);
        this.data = data;
    }
}

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

const parseUrl = (uri) => {
    const loginResponseURI = new URL(uri);
    const accessToken = loginResponseURI.searchParams.get('access_token');
    const idToken = loginResponseURI.searchParams.get('id_token')
    const expiresIn = parseInt(
        loginResponseURI.searchParams.get('expires_in'));

    return { accessToken, idToken, expiresIn };
}

// Get riot client version

const getUserAgent = () => axios({
    method: "GET",
    url: "https://valorant-api.com/v1/version",
})


// Prepare cookies for the auth request

const createSession = (client) => axios({
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

// either returns access token or sends out a 2fa email
const login = (cookie, username, password) => axios({
    url: 'https://auth.riotgames.com/api/v1/authorization',
    method: 'PUT',
    headers: {
        Cookie: cookie,
        "User-Agent": "RiotClient/08.04.00.2324912 rso-auth (Windows; 10;;Professional, x64)"
    },
    data: {
        type: 'auth',
        username,
        password
    },
    httpsAgent: agent
});

const getClientVersion = async () => {

    const data = await getUserAgent()
    return await data.data
}

const auth = async (username, password) => {

    const clientVer = await getClientVersion()
    const session = await createSession(clientVer.data.riotClientBuild)

    let asidCookie = session.headers["set-cookie"].find(cookie => /^asid/.test(cookie));
    
    const loginResponse = await login(asidCookie, username, password)

    return await loginResponse
}

try {
    auth("FABBYSAM", "Shubham@5959").then(resp => {

        if (typeof resp.data.error !== "undefined") {
            console.dir(resp.data)
            if (resp.data.error === "auth_failure")
                throw new ValReauthScriptError("invalid login credentials");
            throw new ValReauthScriptError("unknown error", loginResponse.data);
        }

        let tokens = parseUrl(resp.data.response.parameters.uri)
        console.log(tokens)
    })
}
catch (err) {
    console.warn(err)
}