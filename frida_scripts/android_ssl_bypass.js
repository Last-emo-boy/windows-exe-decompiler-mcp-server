/**
 * Android SSL pinning bypass via Frida.
 * Hooks common SSL verification methods in Java and native layers.
 */

Java.perform(function () {
    // --- TrustManager bypass ---
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    if (TrustManagerImpl) {
        try {
            TrustManagerImpl.verifyChain.overload(
                '[Ljava.security.cert.X509Certificate;',
                'java.lang.String',
                'java.net.Socket',
                'boolean',
                '[B'
            ).implementation = function (untrustedChain) {
                send({ type: 'ssl_bypass', method: 'TrustManagerImpl.verifyChain', status: 'bypassed' });
                return untrustedChain;
            };
        } catch (e) { /* method signature varies by Android version */ }
    }

    // --- X509TrustManager bypass ---
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'com.mcp.BypassTrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) { },
            checkServerTrusted: function (chain, authType) { },
            getAcceptedIssuers: function () { return []; },
        }
    });

    try {
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, [TrustManager.$new()], null);
        send({ type: 'ssl_bypass', method: 'SSLContext.init', status: 'global_bypass_installed' });
    } catch (e) {
        send({ type: 'ssl_bypass', method: 'SSLContext.init', status: 'failed', error: e.toString() });
    }

    // --- OkHttp3 CertificatePinner bypass ---
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
            send({ type: 'ssl_bypass', method: 'OkHttp3.CertificatePinner.check', status: 'bypassed' });
        };
    } catch (e) { /* OkHttp not present */ }

    // --- Retrofit / Volley common patterns ---
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAll = Java.registerClass({
            name: 'com.mcp.AllowAllHostnames',
            implements: [HostnameVerifier],
            methods: {
                verify: function () { return true; }
            }
        });
        send({ type: 'ssl_bypass', method: 'HostnameVerifier', status: 'AllowAll_registered' });
    } catch (e) { /* */ }
});
