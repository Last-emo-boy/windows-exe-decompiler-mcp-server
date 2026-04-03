/**
 * Android crypto API tracer via Frida.
 * Hooks javax.crypto and java.security classes to log encryption/decryption operations,
 * keys, IVs, algorithms, and data samples.
 */

Java.perform(function () {
    // --- Cipher operations ---
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        send({ type: 'crypto_trace', event: 'Cipher.getInstance', transformation: transformation });
        return this.getInstance(transformation);
    };

    Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
        var modeStr = mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : 'mode_' + mode;
        var algo = key.getAlgorithm();
        var encoded = key.getEncoded();
        var keyHex = encoded ? Array.prototype.map.call(Java.array('byte', encoded),
            function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('') : null;
        send({
            type: 'crypto_trace', event: 'Cipher.init',
            mode: modeStr, algorithm: algo, key_hex: keyHex, key_length: encoded ? encoded.length * 8 : 0,
        });
        return this.init(mode, key);
    };

    Cipher.doFinal.overload('[B').implementation = function (input) {
        var inputSample = input ? Array.prototype.map.call(Java.array('byte', input).slice(0, 32),
            function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('') : null;
        var result = this.doFinal(input);
        var outputSample = result ? Array.prototype.map.call(Java.array('byte', result).slice(0, 32),
            function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('') : null;
        send({
            type: 'crypto_trace', event: 'Cipher.doFinal',
            input_preview: inputSample, output_preview: outputSample,
            input_len: input ? input.length : 0, output_len: result ? result.length : 0,
        });
        return result;
    };

    // --- MessageDigest (hash) ---
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function (algo) {
        send({ type: 'crypto_trace', event: 'MessageDigest.getInstance', algorithm: algo });
        return this.getInstance(algo);
    };

    MessageDigest.digest.overload('[B').implementation = function (input) {
        var result = this.digest(input);
        var hashHex = result ? Array.prototype.map.call(Java.array('byte', result),
            function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('') : null;
        send({
            type: 'crypto_trace', event: 'MessageDigest.digest',
            input_len: input ? input.length : 0, hash: hashHex,
        });
        return result;
    };

    // --- SecretKeySpec ---
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
        var keyHex = Array.prototype.map.call(Java.array('byte', key),
            function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
        send({
            type: 'crypto_trace', event: 'SecretKeySpec.new',
            algorithm: algo, key_hex: keyHex, key_bits: key.length * 8,
        });
        return this.$init(key, algo);
    };

    // --- IvParameterSpec ---
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function (iv) {
        var ivHex = Array.prototype.map.call(Java.array('byte', iv),
            function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
        send({ type: 'crypto_trace', event: 'IvParameterSpec.new', iv_hex: ivHex, iv_bits: iv.length * 8 });
        return this.$init(iv);
    };

    // --- SharedPreferences for stored keys ---
    try {
        var SharedPrefsImpl = Java.use('android.app.SharedPreferencesImpl');
        SharedPrefsImpl.getString.implementation = function (key, defValue) {
            var val = this.getString(key, defValue);
            if (key.toLowerCase().indexOf('key') !== -1 || key.toLowerCase().indexOf('secret') !== -1 ||
                key.toLowerCase().indexOf('token') !== -1 || key.toLowerCase().indexOf('password') !== -1) {
                send({ type: 'crypto_trace', event: 'SharedPrefs.getString', key: key, value_preview: val ? val.substring(0, 64) : null });
            }
            return val;
        };
    } catch (e) { /* */ }

    send({ type: 'crypto_trace', status: 'hooks_installed' });
});
