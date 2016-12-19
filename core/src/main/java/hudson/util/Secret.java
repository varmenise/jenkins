/*
 * The MIT License
 * 
 * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi
 * Copyright (c) 2016, CloudBees Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.util;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import com.trilead.ssh2.crypto.Base64;
import jenkins.model.Jenkins;
import hudson.Util;
import jenkins.security.CryptoConfidentialKey;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.Stapler;

import javax.crypto.Cipher;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.regex.Pattern;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Glorified {@link String} that uses encryption in the persisted form, to avoid accidental exposure of a secret.
 *
 * <p>
 * This is not meant as a protection against code running in the same VM, nor against an attacker
 * who has local file system access on Jenkins master.
 *
 * <p>
 * {@link Secret}s can correctly read-in plain text password, so this allows the existing
 * String field to be updated to {@link Secret}.
 *
 * @author Kohsuke Kawaguchi
 */
public final class Secret implements Serializable {
    /**
     * Unencrypted secret text.
     */
    private final String value;
    private byte[] iv;

    /*package*/ Secret(String value) {
        this.value = value;
    }

    /*package*/ Secret(String value, byte[] iv) {
        this.value = value;
        this.iv = iv;
    }

    /**
     * Obtains the secret in a plain text.
     *
     * @see #getEncryptedValue()
     * @deprecated as of 1.356
     *      Use {@link #toString(Secret)} to avoid NPE in case Secret is null.
     *      Or if you really know what you are doing, use the {@link #getPlainText()} method.
     */
    @Override
    @Deprecated
    public String toString() {
        return value;
    }

    /**
     * Obtains the plain text password.
     * Before using this method, ask yourself if you'd be better off using {@link Secret#toString(Secret)}
     * to avoid NPE.
     */
    public String getPlainText() {
        return value;
    }

    @Override
    public boolean equals(Object that) {
        return that instanceof Secret && value.equals(((Secret)that).value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    /**
     * Encrypts {@link #value} and returns it in an encoded printable form.
     *
     * @see #toString() 
     */
    public String getEncryptedValue() {
        try {
            synchronized (this) {
                if (iv == null) { //if we were created from plain text or other reason without iv
                    iv = KEY.newIv();
                }
            }
            JSONObject data = new JSONObject();
            data.put("iv", new String(Base64.encode(iv)));
            Cipher cipher = KEY.encrypt(iv);
            data.put("secret", new String(Base64.encode(cipher.doFinal(this.value.getBytes(UTF_8)))));
            StringBuilder str = new StringBuilder("{");
            str.append(Base64.encode(data.toString().getBytes(UTF_8)));
            str.append("}");
            return str.toString();
        } catch (GeneralSecurityException e) {
            throw new Error(e); // impossible
        }
    }

    /**
     * Pattern matching a possible output of {@link #getEncryptedValue} possibly containing metadata.
     * Basically, any Base64-encoded value.
     * You must then call {@link #decrypt} to eliminate false positives.
     */
    @Restricted(NoExternalUse.class)
    public static final Pattern ENCRYPTED_VALUE_PATTERN = Pattern.compile("\\{?[A-Za-z0-9+/]+={0,2}\\}?");

    /**
     * Pattern matching a possible output of {@link #getEncryptedValue} containing metadata.
     * Basically, any Base64-encoded value surrounded by <code>{</code> and <code>}</code>.
     * You must then call {@link #decrypt} to eliminate false positives.
     */
    @Restricted(NoExternalUse.class)
    public static final Pattern ENCRYPTED_META_VALUE_PATTERN = Pattern.compile("\\{[A-Za-z0-9+/]+={0,2}\\}?");

    /**
     * Reverse operation of {@link #getEncryptedValue()}. Returns null
     * if the given cipher text was invalid.
     */
    public static Secret decrypt(String data) {
        if (data == null) return null;

        if (ENCRYPTED_META_VALUE_PATTERN.matcher(data).matches()) { //likely CBC encrypted/containing metadata but could be plain text
            try {
                String stripped = data.substring(1, data.length() - 1);
                JSONObject json = JSONObject.fromObject(new String(Base64.decode(stripped.toCharArray()), UTF_8));
                byte[] iv = Base64.decode(json.getString("iv").toCharArray());
                byte[] code = Base64.decode(json.getString("secret").toCharArray());
                String text = new String(KEY.decrypt(iv).doFinal(code), UTF_8);
                return new Secret(text, iv);
            } catch (GeneralSecurityException | JSONException e) {
                try {
                    return HistoricalSecrets.decrypt(data, KEY);
                } catch (IOException | GeneralSecurityException e1) {
                    return null;
                }
            } catch (IOException e) {
                return null;
            }
        }
        try {
            return HistoricalSecrets.decrypt(data, KEY);
        } catch (GeneralSecurityException e) {
            return null;
        } catch (UnsupportedEncodingException e) {
            throw new Error(e); // impossible
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Workaround for JENKINS-6459 / http://java.net/jira/browse/GLASSFISH-11862
     * This method uses specific provider selected via hudson.util.Secret.provider system property
     * to provide a workaround for the above bug where default provide gives an unusable instance.
     * (Glassfish Enterprise users should set value of this property to "SunJCE")
     */
    public static Cipher getCipher(String algorithm) throws GeneralSecurityException {
        return PROVIDER != null ? Cipher.getInstance(algorithm, PROVIDER)
                                : Cipher.getInstance(algorithm);
    }

    /**
     * Attempts to treat the given string first as a cipher text, and if it doesn't work,
     * treat the given string as the unencrypted secret value.
     *
     * <p>
     * Useful for recovering a value from a form field.
     *
     * @return never null
     */
    public static Secret fromString(String data) {
        data = Util.fixNull(data);
        Secret s = decrypt(data);
        if(s==null) s=new Secret(data);
        return s;
    }

    /**
     * Works just like {@link Secret#toString()} but avoids NPE when the secret is null.
     * To be consistent with {@link #fromString(String)}, this method doesn't distinguish
     * empty password and null password.
     */
    public static String toString(Secret s) {
        return s==null ? "" : s.value;
    }

    public static final class ConverterImpl implements Converter {
        public ConverterImpl() {
        }

        public boolean canConvert(Class type) {
            return type==Secret.class;
        }

        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
            Secret src = (Secret) source;
            writer.setValue(src.getEncryptedValue());
        }

        public Object unmarshal(HierarchicalStreamReader reader, final UnmarshallingContext context) {
            return fromString(reader.getValue());
        }
    }

    /**
     * Workaround for JENKINS-6459 / http://java.net/jira/browse/GLASSFISH-11862
     * @see #getCipher(String)
     */
    private static final String PROVIDER = System.getProperty(Secret.class.getName()+".provider");

    /**
     * For testing only. Override the secret key so that we can test this class without {@link Jenkins}.
     */
    /*package*/ static String SECRET = null;

    /**
     * The key that encrypts the data on disk.
     */
    private static final CryptoConfidentialKey KEY = new CryptoConfidentialKey(Secret.class.getName());

    private static final long serialVersionUID = 1L;

    static {
        Stapler.CONVERT_UTILS.register(new org.apache.commons.beanutils.Converter() {
            public Secret convert(Class type, Object value) {
                return Secret.fromString(value.toString());
            }
        }, Secret.class);
    }
}
