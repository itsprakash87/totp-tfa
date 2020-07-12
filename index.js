'use strict'

// ********************************************************************************************
// A complete library to add totp based two factor authentication system in the application.
// ********************************************************************************************

var base32 = require('base32.js');
var crypto = require('crypto');
var qrImage = require('qr-image');

// Private util functions

var getRandomNumber = function (min, max) {
    // Generate a random number between min and max inclusive.
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

var getByteArray = function (counter) {
    // Return an array of bytes after splitting the number into individual bytes.
    var byteArray = new Array(8);
    for (var i = byteArray.length - 1; i >= 0; i--) {
        byteArray[i] = counter & 0xff;
        counter = counter >> 8;
    }
    return byteArray;
}

// Shared functions

/**
 * This method create and return a random  secret code.
 * @param {Integer} [keyLength = 25] Length of the secret key.
 * @return {String} A random secret key.
 */

exports.generateSecretCode = function (keyLength) {
    // Generate a random secret code of given keyLength or 25.
    // The generated secret code may contain characters a-z and 1-9
    try {
        keyLength = keyLength || 25;

        var key = '';
        var keyCharacter = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

        var min = 0;
        var max = keyCharacter.length - 1;

        for (var i = 0; i < keyLength; i++) {
            key += keyCharacter[getRandomNumber(min, max)];
        }
        return key;
    } catch (err) {
        console.error(err)
        throw new Error(err);
    }
}

/**
 * This method generates the qr image of the given secret code. It returns a promise.
 *
 * @param {Object} obj
 * @param {String} obj.secretCode The secret code.
 * @param {String} [obj.name = "Secret"] Name of the application/company which will be displayed in google authenticator (or similar) apps along with the generated token.
 * @param {String} [obj.userAccount = "Secret"] Name/userid/emailid of the user which will be displayed in google authenticator (or similar) apps along with the generated token.
 * @return {String} Returns a promise which on resolve return a base64 decoded string of the qr image. Putting this string in src attribute of the img tag would display the image.
 */

exports.generateQrImage = function (obj) {
    return new Promise(function (resolve, reject) {
        try {
            var name = obj.name || 'Secret';
            var userAccount = obj.userAccount || 'Secret';
            var secretCode = obj.secretCode;

            if (!secretCode) {
                console.error("Secret code is required.")
                reject("Secret code is required.");
                return;
            }

            var secret = base32.encode(Buffer(secretCode)).toString().replace(/=/g, '');

            var otpauth = 'otpauth://totp/' + encodeURIComponent(userAccount) +
                '?issuer=' + encodeURIComponent(name) +
                '&secret=' + secret;

            var qrImageStream = qrImage.image(otpauth, { type: 'png' });
            var qrImageData = [];
            qrImageStream.on('data', function (data) { qrImageData.push(data); });
            qrImageStream.on('end', function () {
                var finalQrImage = 'data:image/png;base64,' + Buffer.concat(qrImageData).toString('base64')
                resolve(finalQrImage);
            });
        } catch (err) {
            reject(err);
        }
    })
}

/**
 * Instead of calling two separate methods for generating secret and generating its qr image, this method can be called which return both (i.e. secret code and the corresponding qr image).
 * It returns a promise.
 *
 * @param {Object} obj
 * @param {Integer} [obj.keyLength = 25] Length of secret key.
 * @param {String} [obj.name = "Secret"] Name of the application/company which will be displayed in google authenticator (or similar) apps with the generated token.
 * @param {String} [obj.userAccount = "Secret"] Name/userid/emailid of the user which will be displayed in google authenticator (or similar) apps with the generated token.
 * @return {Object} An object which contain secret code (secretCode) and qr image (qrImage).
 */

exports.generateSecretAndQr = function (obj) {
    return new Promise(function (resolve, reject) {
        var keyLength = obj.keyLength;
        var name = obj.name;
        var userAccount = obj.userAccount;

        obj.secretCode = exports.generateSecretCode(keyLength);

        exports.generateQrImage(obj).then(function (qrImage) {
            obj.qrImage = qrImage;
            resolve({ secretCode: obj.secretCode, qrImage: obj.qrImage });
        }).catch(function (err) {
            reject(err);
        })
    })
}

/**
 * Generate a HMAC based one time password with the given secretKey, and counter.
 *
 * @param {Object} obj
 * @param {Integer} obj.counter Counter for hotp code.
 * @param {Integer} [obj.codeLength = 6] The length of the code to be generated.
 * @param {String} obj.secretKey The secret key for hotp code.
 * @return {String} The HMAC based one time password.
 */

exports.hotp = function (obj) {
    try {
        var secretKey = obj.secretKey;
        var counter = obj.counter;
        var codeLength = obj.codeLength || 6;

        if (!secretKey) {
            console.error("secretKey is required.")
            throw new Error("secretKey is required.");
            return;
        }
        else if(!counter){
            console.error("counter is required.")
            throw new Error("counter is required.");
            return;
        }

        var hmacObj = crypto.createHmac('sha1', secretKey);
        var hash = hmacObj.update(new Buffer(getByteArray(counter))).digest();

        var offset = hash[19] & 0xf;
        var truncatedHash =
            (hash[offset++] & 0x7f) << 24 |
            (hash[offset++] & 0xff) << 16 |
            (hash[offset++] & 0xff) << 8 |
            (hash[offset++] & 0xff);

        var finalCode = (Number(truncatedHash) % 1000000).toString();

        while (finalCode.length < codeLength) {
            finalCode = '0' + finalCode;
        }

        return finalCode;
    } catch (err) {
        console.error(err);
        throw new Error(err)
    }
}

/**
 * For a given token and secret key, verify if the token is valid or not.
 *
 * @param {Object} obj
 * @param {String} obj.secretKey The secret key.
 * @param {String} obj.userToken The token to be verified.
 * @param {Integer} [obj.step = 30] The number of seconds each step should have. Usually its value should be kept default.
 * @param {Integer} [obj.allow = 0] Number of last and upcoming tokens which should be considered valid. 
 * For example if the given value is 1 then one token which was generated before current token and one token which will be generated after this token will also be considered valid.
 * @return {Boolean} Token is valid or not.
 */

exports.verify = function (obj) {
    try {
        var secretKey = obj.secretKey;
        var userToken = obj.userToken;
        var step = obj.step || 30;
        var allow = obj.allow || 0;

        if (!secretKey) {
            console.error("secretKey is required.")
            throw new Error("secretKey is required.");
            return;
        }
        else if(!userToken){
            console.error("userToken is required.")
            throw new Error("userToken is required.");
            return;
        }

        var counter = Math.floor(Date.now() / 1000 / step);
        var verified = false;

        for (var i = counter - allow; i <= counter + allow; i++) {
            obj.counter = i;
            if (exports.hotp(obj) === userToken) {
                verified = true;
                break;
            }
        }

        return verified;
    } catch (err) {
        console.error(err);
        throw new Error(err)
    }
}
