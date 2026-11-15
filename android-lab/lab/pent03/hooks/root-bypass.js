/*
 * root-bypass.js
 * ------------------------------------------------------------------------
 * Bypasses: common root-detection checks that stop an app from running on a
 *   rooted/emulated lab device, so dynamic analysis can proceed. Covers:
 *     - File.exists() probes for su / Magisk / busybox paths
 *     - Runtime.exec("su" / "which su")
 *     - build-tag / "test-keys" checks (android.os.Build.TAGS)
 *     - RootBeer.isRooted() (and its individual checks) when present
 * Logs each neutralised check; modifies nothing else.
 *
 * Load it:
 *     frida -U -f com.securebank.mobile -l root-bypass.js --no-pause
 * frida-server must be running on the device.
 *
 * AUTHORIZATION ONLY. Lab-owned or written-authorization apps, isolated
 * emulator only.
 */
'use strict';

function log(msg) {
  console.log('[root-bypass] ' + msg);
}

var ROOT_PATHS = [
  '/system/app/Superuser.apk',
  '/sbin/su',
  '/system/bin/su',
  '/system/xbin/su',
  '/data/local/xbin/su',
  '/data/local/bin/su',
  '/system/sd/xbin/su',
  '/system/bin/failsafe/su',
  '/data/local/su',
  '/su/bin/su',
  '/system/xbin/busybox',
  '/sbin/magisk',
  '/data/adb/magisk',
];

Java.perform(function () {
  log('starting root-detection bypass (lab use only)');

  // 1. File.exists() for known su/magisk paths.
  try {
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      if (ROOT_PATHS.indexOf(path) !== -1) {
        log('File.exists(' + path + ') -> false');
        return false;
      }
      return this.exists();
    };
    log('hooked java.io.File.exists');
  } catch (e) {
    log('File.exists hook skipped: ' + e);
  }

  // 2. Runtime.exec("su" / "which su").
  try {
    var Runtime = Java.use('java.lang.Runtime');
    var exec1 = Runtime.exec.overload('java.lang.String');
    exec1.implementation = function (cmd) {
      if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1)) {
        log('Runtime.exec(' + cmd + ') -> blocked');
        return exec1.call(this, 'echo');
      }
      return exec1.call(this, cmd);
    };
    log('hooked Runtime.exec');
  } catch (e) {
    log('Runtime.exec hook skipped: ' + e);
  }

  // 3. Build.TAGS "test-keys".
  try {
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    log('set Build.TAGS -> release-keys');
  } catch (e) {
    /* field may be final on some runtimes */
  }

  // 4. RootBeer, when the app bundles it.
  try {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function () {
      log('RootBeer.isRooted -> false');
      return false;
    };
    log('hooked RootBeer.isRooted');
  } catch (e) {
    /* RootBeer not bundled */
  }

  log('root-detection checks neutralised');
});
