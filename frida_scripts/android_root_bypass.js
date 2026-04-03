/**
 * Android root detection bypass via Frida.
 * Hooks common root-checking methods to return non-rooted status.
 */

Java.perform(function () {
    // --- File.exists bypass for su / magisk paths ---
    var File = Java.use('java.io.File');
    var rootPaths = [
        '/system/app/Superuser.apk', '/system/xbin/su', '/system/bin/su',
        '/sbin/su', '/data/local/su', '/data/local/bin/su',
        '/data/local/xbin/su', '/system/sd/xbin/su',
        '/system/bin/.ext/.su', '/system/usr/we-need-root/su-backup',
        '/system/xbin/busybox', '/dev/magisk/mirror',
    ];

    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i] || path.indexOf('magisk') !== -1 || path.indexOf('Superuser') !== -1) {
                send({ type: 'root_bypass', method: 'File.exists', path: path, spoofed: true });
                return false;
            }
        }
        return this.exists();
    };

    // --- Runtime.exec bypass for 'su', 'which su' ---
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
        var cmd = cmdArray.join(' ');
        if (cmd.indexOf('su') !== -1 || cmd.indexOf('magisk') !== -1) {
            send({ type: 'root_bypass', method: 'Runtime.exec', command: cmd, spoofed: true });
            throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return this.exec(cmdArray);
    };

    // --- Build.TAGS bypass ---
    try {
        var Build = Java.use('android.os.Build');
        var tags = Build.TAGS.value;
        if (tags && tags.indexOf('test-keys') !== -1) {
            Build.TAGS.value = 'release-keys';
            send({ type: 'root_bypass', method: 'Build.TAGS', original: tags, spoofed: 'release-keys' });
        }
    } catch (e) { /* */ }

    // --- SystemProperties bypass ---
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            if (key === 'ro.build.selinux') {
                send({ type: 'root_bypass', method: 'SystemProperties.get', key: key, spoofed: '1' });
                return '1';
            }
            if (key === 'ro.debuggable') {
                send({ type: 'root_bypass', method: 'SystemProperties.get', key: key, spoofed: '0' });
                return '0';
            }
            return this.get(key);
        };
    } catch (e) { /* */ }

    // --- Common root detection library: RootBeer ---
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function () {
            send({ type: 'root_bypass', method: 'RootBeer.isRooted', spoofed: false });
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () { return false; };
    } catch (e) { /* RootBeer not present */ }

    send({ type: 'root_bypass', status: 'hooks_installed' });
});
