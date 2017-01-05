package com.codename1.security.certfingerprint.impl;

import com.codename1.io.Log;
import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.Certificate;

public class CheckCertInternalImpl implements CheckCertInternal {

    private static final char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    public void checkCert(String param) {
        try {
            String fp = getFingerprint(param);
            Impl.success(fp);
        } catch(Exception err) {
            Log.e(err);
            Impl.fail(err.toString());
        }
    }

    public boolean isSupported() {
        return true;
    }

    private static String getFingerprint(String httpsURL) throws Exception {
        final HttpsURLConnection con = (HttpsURLConnection) new URL(httpsURL).openConnection();
        con.setConnectTimeout(5000);
        con.connect();
        final Certificate cert = con.getServerCertificates()[0];
        final MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(cert.getEncoded());
        return dumpHex(md.digest());
    }

    private static String dumpHex(byte[] data) {
        final int n = data.length;
        final StringBuilder sb = new StringBuilder(n * 3 - 1);
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(HEX_CHARS[(data[i] >> 4) & 0x0F]);
            sb.append(HEX_CHARS[data[i] & 0x0F]);
        }
        return sb.toString();
    }
}
