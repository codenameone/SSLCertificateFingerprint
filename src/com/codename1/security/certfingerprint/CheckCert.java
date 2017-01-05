/*
 * Copyright (c) 2012, Codename One and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Codename One designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *  
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 * 
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * Please contact Codename One through http://www.codenameone.com/ if you 
 * need additional information or have any questions.
 */

package com.codename1.security.certfingerprint;

import com.codename1.io.Util;
import com.codename1.security.certfingerprint.impl.CheckCertInternal;
import com.codename1.security.certfingerprint.impl.Impl;
import com.codename1.system.NativeLookup;
import com.codename1.ui.Display;
import com.codename1.util.FailureCallback;
import com.codename1.util.SuccessCallback;
import java.io.IOException;

/**
 * Checks the certificate fingerprint for the given server URL
 */
public class CheckCert {
    private static CheckCertInternal nat;
    private static final Object LOCK = new Object();

    // stupid C optimizer deletes unused methods
    static {
        Impl.fail(null);
        Impl.success(null);
    }
    
    private static CheckCertInternal getImpl() {
        if(nat == null) {
            nat = NativeLookup.create(CheckCertInternal.class);
        }
        return nat;
    }
    
    /**
     * Returns true if this functionality is supported on this OS
     */
    public static boolean isCertCheckingSupported() {
        CheckCertInternal c = getImpl();
        return c != null && c.isSupported();
    }

    /**
     * Queries the server for the certificate and validates it, returns the fingerprint
     */
    public static String getFingerprint(String url) throws IOException {
        class Waiter implements SuccessCallback<String>, FailureCallback<String>, Runnable {
            private String result;
            private String error;
            
            @Override
            public void onSucess(String value) {
                synchronized(LOCK) {
                    result = value;
                    LOCK.notify();
                }
            }

            @Override
            public void onError(Object sender, Throwable err, int errorCode, String errorMessage) {
                synchronized(LOCK) {
                    error = errorMessage;
                    LOCK.notify();
                }
            }

            @Override
            public void run() {
                synchronized(LOCK) {
                    while(result == null && error == null) {
                        Util.wait(LOCK, 500);
                    }
                }
            }
        }
        
        Waiter w = new Waiter();
        getFingerprint(url, w, w);
        Display.getInstance().invokeAndBlock(w);
        if(w.error != null) {
            throw new IOException(w.error);
        }
        return w.result;
    }
    
    /**
     * Queries the server for the certificate and validates it, returns the fingerprint via a callback.
     * The method returns immediately and preforms the query asynchronously
     */
    public static void getFingerprint(String url, SuccessCallback<String> callback, FailureCallback<String> err) {
        CheckCertInternal c = getImpl();
        if(c != null && c.isSupported()) {
            Impl.listen(callback, err);
            c.checkCert(url);
        } else {
            err.onError(url, null, 1, "Fingerprint certificate unsupported in this platform");
        }
    }
}
