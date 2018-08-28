const express = require('express');
const fetch = require('node-fetch');
const rs = require('jsrsasign');

const app = express();

app.get('/activate', (req, res) => {
    // IDトークンを取得
    const token = req.header('x-amzn-oidc-data');

    // ヘッダーからkey idを取得
    const decodedJwt = rs.KJUR.jws.JWS.parse(token);
    const kid = decodedJwt.headerObj.kid;

    // 検証用の公開鍵を取得
    fetch(`https://public-keys.auth.elb.ap-northeast-1.amazonaws.com/${kid}`).then(response => {
        return response.text();
    }).then(pem => {
        // トークンを検証
        const pubKey = rs.KEYUTIL.getKey(pem);
        const isValid = rs.KJUR.jws.JWS.verify(token, pubKey, ["ES256"]);
        if (isValid) {
            res.send('valid');
        } else {
            res.status(400).send('invalid');
        }
    });
});

app.get('/', (req, res) => {
    res.send('arrived!');
});

app.listen(3000);
