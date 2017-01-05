# SSL Certificate Fingerprint

Certificate pinning happens when an attacker can "fake" a server but do so with a certificate that is seamingly valid e.g. one that was obtained from a valid certificate authority. This is a difficult attack to execute and so the vulnerability isn't crucial for most applications unless you are targeting sensitive industries such as banking/government etc.

This API essentially validates that the connection to the server has the same "fingerprint" (certificate hash) as you had during the development of the application. Currently this API works in the simulator, desktop ports, iOS & Android. In other OS's `isSupported()` will return false.

Usage of the library is demonstrated in the `TestFingerprint` demo project within. To use the API just invoke:

````java
if(CheckCert.isCertCheckingSupported()) {
    String f = CheckCert.getFingerprint(myHttpsURL);
    if(validKeysList.contains(f)) {
        // OK it's a good certificate proceed
    } else {
       if(Dialog.show("Security Warning", "WARNING: it is possible your commmunications are being tampered! We suggest quitting the app at once!", "Quit", "Continue")) {
          Display.getInstance().exitApplication();
       }
    }
} else {
    // certificate fingerprint checking isn't supported on this platform... It's your decision whether to proceed or not
}
````
