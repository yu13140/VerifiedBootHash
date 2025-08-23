/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.xtrlumen.vbmeta.attestation;

import android.util.Base64;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Parses an attestation certificate and provides an easy-to-use interface for examining the contents.
 */
public abstract class Attestation {
    static final String ASN1_OID = "1.3.6.1.4.1.11129.2.1.17";
    static final String KEY_USAGE_OID = "2.5.29.15"; // Standard key usage extension.

    public static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
    public static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int KM_SECURITY_LEVEL_STRONG_BOX = 2;

    int attestationVersion;
    int keymasterVersion;
    int keymasterSecurityLevel;
    byte[] attestationChallenge;
    byte[] uniqueId;
    AuthorizationList softwareEnforced;
    AuthorizationList teeEnforced;
    Set<String> unexpectedExtensionOids;

    /**
     * Constructs an {@code Attestation} object from the provided {@link X509Certificate},
     * extracting the attestation data from the attestation extension.
     *
     * <p>This method ensures that at most one attestation extension is included in the certificate.
     *
     * @throws CertificateParsingException if the certificate does not contain a properly-formatted
     *                                     attestation extension, if it contains multiple attestation extensions, or if the
     *                                     attestation extension can not be parsed.
     */

    public static Attestation loadFromCertificate(X509Certificate x509Cert) throws CertificateParsingException {
        if (x509Cert.getExtensionValue(ASN1_OID) == null) {
            throw new CertificateParsingException("No ASN.1 attestation extension found");
        }
        return new Asn1Attestation(x509Cert);
    }

    Attestation(X509Certificate x509Cert) {
        unexpectedExtensionOids = retrieveUnexpectedExtensionOids(x509Cert);
    }

    public static String securityLevelToString(int attestationSecurityLevel) {
        return switch (attestationSecurityLevel) {
            case KM_SECURITY_LEVEL_SOFTWARE -> "Software";
            case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE";
            case KM_SECURITY_LEVEL_STRONG_BOX -> "StrongBox";
            default -> "Unknown (" + attestationSecurityLevel + ")";
        };
    }

    public static String attestationVersionToString(int version) {
        return switch (version) {
            case 1 -> "Keymaster 2.0";
            case 2 -> "Keymaster 3.0";
            case 3 -> "Keymaster 4.0";
            case 4 -> "Keymaster 4.1";
            case 100 -> "KeyMint 1.0";
            case 200 -> "KeyMint 2.0";
            case 300 -> "KeyMint 3.0";
            case 400 -> "KeyMint 4.0";
            default -> "Unknown (" + version + ")";
        };
    }

    public static String keymasterVersionToString(int version) {
        return switch (version) {
            case 0 -> "Keymaster 0.2 or 0.3";
            case 1 -> "Keymaster 1.0";
            case 2 -> "Keymaster 2.0";
            case 3 -> "Keymaster 3.0";
            case 4 -> "Keymaster 4.0";
            case 41 -> "Keymaster 4.1";
            case 100 -> "KeyMint 1.0";
            case 200 -> "KeyMint 2.0";
            case 300 -> "KeyMint 3.0";
            case 400 -> "KeyMint 4.0";
            default -> "Unknown (" + version + ")";
        };
    }

    public int getAttestationVersion() {
        return attestationVersion;
    }

    public abstract int getAttestationSecurityLevel();

    public abstract RootOfTrust getRootOfTrust();

    // Returns one of the KM_VERSION_* values define above.
    public int getKeymasterVersion() {
        return keymasterVersion;
    }

    public int getKeymasterSecurityLevel() {
        return keymasterSecurityLevel;
    }

    public byte[] getAttestationChallenge() {
        return attestationChallenge;
    }

    public byte[] getUniqueId() {
        return uniqueId;
    }

    public AuthorizationList getSoftwareEnforced() {
        return softwareEnforced;
    }

    public AuthorizationList getTeeEnforced() {
        return teeEnforced;
    }

    public Set<String> getUnexpectedExtensionOids() {
        return unexpectedExtensionOids;
    }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append("Extension type: " + getClass());
        s.append("\nAttest version: " + attestationVersionToString(attestationVersion));
        s.append("\nAttest security: " + securityLevelToString(getAttestationSecurityLevel()));
        s.append("\nKM version: " + keymasterVersionToString(keymasterVersion));
        s.append("\nKM security: " + securityLevelToString(keymasterSecurityLevel));

        s.append("\nChallenge");
        String stringChallenge =
                attestationChallenge != null ? new String(attestationChallenge) : "";
        if (Arrays.equals(attestationChallenge, stringChallenge.getBytes())) {
            s.append(": [" + stringChallenge + "]");
        } else if (attestationChallenge != null) {
            s.append(" (base64): [" + Base64.encodeToString(attestationChallenge, 0) + "]");
        }
        if (uniqueId != null) {
            s.append("\nUnique ID: [" + toHexLower(uniqueId) + "]");
        }

        s.append("\n-- SW enforced --");
        s.append(softwareEnforced);
        s.append("\n-- TEE enforced --");
        s.append(teeEnforced);

        return s.toString();
    }

    Set<String> retrieveUnexpectedExtensionOids(X509Certificate x509Cert) {
        Set<String> set = new HashSet<>();
        var critical = x509Cert.getCriticalExtensionOIDs();
        if (critical != null) {
            for (var s : critical) {
                if (!KEY_USAGE_OID.equals(s)) set.add(s);
            }
        }
        var nonCritical = x509Cert.getNonCriticalExtensionOIDs();
        if (nonCritical != null) {
            for (var s : nonCritical) {
                if (!ASN1_OID.equals(s)) set.add(s);
            }
        }
        return set;
    }

    private static String toHexLower(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            int v = b & 0xFF;
            sb.append(Character.forDigit((v >>> 4), 16));
            sb.append(Character.forDigit((v & 0x0F), 16));
        }
        return sb.toString();
    }
}

/*
 * Below are merged implementations from former Asn1Attestation.java and Asn1Utils.java
 * consolidated into this file as package-private classes to keep API compatibility
 * without altering other callers.
 */

class Asn1Attestation extends Attestation {
    static final int ATTESTATION_VERSION_INDEX = 0;
    static final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
    static final int KEYMASTER_VERSION_INDEX = 2;
    static final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
    static final int ATTESTATION_CHALLENGE_INDEX = 4;
    static final int UNIQUE_ID_INDEX = 5;
    static final int SW_ENFORCED_INDEX = 6;
    static final int TEE_ENFORCED_INDEX = 7;

    int attestationSecurityLevel;

    public Asn1Attestation(X509Certificate x509Cert) throws CertificateParsingException {
        super(x509Cert);
        ASN1Sequence seq = getAttestationSequence(x509Cert);

        attestationVersion =
                Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_VERSION_INDEX));
        attestationSecurityLevel =
                Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX));
        keymasterVersion = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_VERSION_INDEX));
        keymasterSecurityLevel =
                Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX));

        attestationChallenge =
                Asn1Utils.getByteArrayFromAsn1(seq.getObjectAt(ATTESTATION_CHALLENGE_INDEX));

        uniqueId = Asn1Utils.getByteArrayFromAsn1(seq.getObjectAt(UNIQUE_ID_INDEX));

        softwareEnforced = new AuthorizationList(seq.getObjectAt(SW_ENFORCED_INDEX));
        teeEnforced = new AuthorizationList(seq.getObjectAt(TEE_ENFORCED_INDEX));
    }

    ASN1Sequence getAttestationSequence(X509Certificate x509Cert)
            throws CertificateParsingException {
        byte[] attestationExtensionBytes = x509Cert.getExtensionValue(Attestation.ASN1_OID);
        if (attestationExtensionBytes == null || attestationExtensionBytes.length == 0) {
            throw new CertificateParsingException("Did not find extension with OID " + ASN1_OID);
        }
        return Asn1Utils.getAsn1SequenceFromBytes(attestationExtensionBytes);
    }

    public int getAttestationSecurityLevel() {
        return attestationSecurityLevel;
    }

    public RootOfTrust getRootOfTrust() {
        RootOfTrust tee = teeEnforced.getRootOfTrust();
        if (tee != null) return tee;
        return softwareEnforced.getRootOfTrust();
    }
}

final class Asn1Utils {

    public static int getIntegerFromAsn1(ASN1Encodable asn1Value)
            throws CertificateParsingException {
        if (asn1Value instanceof ASN1Integer) {
            return bigIntegerToInt(((ASN1Integer) asn1Value).getValue());
        } else if (asn1Value instanceof ASN1Enumerated) {
            return bigIntegerToInt(((ASN1Enumerated) asn1Value).getValue());
        } else {
            throw new CertificateParsingException(
                    "Integer value expected, " + asn1Value.getClass().getName() + " found.");
        }
    }

    public static Long getLongFromAsn1(ASN1Encodable asn1Value) throws CertificateParsingException {
        if (asn1Value instanceof ASN1Integer) {
            return bigIntegerToLong(((ASN1Integer) asn1Value).getValue());
        } else {
            throw new CertificateParsingException(
                    "Integer value expected, " + asn1Value.getClass().getName() + " found.");
        }
    }

    public static byte[] getByteArrayFromAsn1(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof DEROctetString derOctectString)) {
            throw new CertificateParsingException("Expected DEROctetString");
        }
        return derOctectString.getOctets();
    }

    public static ASN1Encodable getAsn1EncodableFromBytes(byte[] bytes)
            throws CertificateParsingException {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(bytes)) {
            return asn1InputStream.readObject();
        } catch (java.io.IOException e) {
            throw new CertificateParsingException("Failed to parse Encodable", e);
        }
    }

    public static ASN1Sequence getAsn1SequenceFromBytes(byte[] bytes)
            throws CertificateParsingException {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(bytes)) {
            return getAsn1SequenceFromStream(asn1InputStream);
        } catch (java.io.IOException e) {
            throw new CertificateParsingException("Failed to parse SEQUENCE", e);
        }
    }

    public static ASN1Sequence getAsn1SequenceFromStream(final ASN1InputStream asn1InputStream)
            throws java.io.IOException, CertificateParsingException {
        ASN1Primitive asn1Primitive = asn1InputStream.readObject();
        if (!(asn1Primitive instanceof ASN1OctetString)) {
            throw new CertificateParsingException(
                    "Expected octet stream, found " + asn1Primitive.getClass().getName());
        }
        try (ASN1InputStream seqInputStream = new ASN1InputStream(
                ((ASN1OctetString) asn1Primitive).getOctets())) {
            asn1Primitive = seqInputStream.readObject();
            if (!(asn1Primitive instanceof ASN1Sequence)) {
                throw new CertificateParsingException(
                        "Expected sequence, found " + asn1Primitive.getClass().getName());
            }
            return (ASN1Sequence) asn1Primitive;
        }
    }

    public static java.util.Set<Integer> getIntegersFromAsn1Set(ASN1Encodable set)
            throws CertificateParsingException {
        if (!(set instanceof ASN1Set)) {
            throw new CertificateParsingException(
                    "Expected set, found " + set.getClass().getName());
        }

        java.util.Set<Integer> out = new java.util.HashSet<>();
        for (java.util.Enumeration<?> e = ((ASN1Set) set).getObjects(); e.hasMoreElements();) {
            out.add(getIntegerFromAsn1((ASN1Integer) e.nextElement()));
        }
        return out;
    }

    public static String getStringFromAsn1OctetStreamAssumingUTF8(ASN1Encodable encodable)
            throws CertificateParsingException {
        if (!(encodable instanceof ASN1OctetString octetString)) {
            throw new CertificateParsingException(
                    "Expected octet string, found " + encodable.getClass().getName());
        }

        return new String(octetString.getOctets(), java.nio.charset.StandardCharsets.UTF_8);
    }

    public static String getStringFromASN1PrintableString(ASN1Encodable encodable)
            throws CertificateParsingException {
        if (!(encodable instanceof ASN1PrintableString printableString)) {
            throw new CertificateParsingException(
                    "Expected printable string, found " + encodable.getClass().getName());
        }
        return printableString.getString();
    }

    public static java.util.Date getDateFromAsn1(ASN1Primitive value) throws CertificateParsingException {
        return new java.util.Date(getLongFromAsn1(value));
    }

    public static boolean getBooleanFromAsn1(ASN1Encodable value)
            throws CertificateParsingException {
        if (!(value instanceof ASN1Boolean booleanValue)) {
            throw new CertificateParsingException(
                    "Expected boolean, found " + value.getClass().getName());
        }
        if (booleanValue.equals(ASN1Boolean.TRUE)) {
            return true;
        } else if (booleanValue.equals((ASN1Boolean.FALSE))) {
            return false;
        }

        throw new CertificateParsingException(
                "DER-encoded boolean values must contain either 0x00 or 0xFF");
    }

    private static int bigIntegerToInt(java.math.BigInteger bigInt) throws CertificateParsingException {
        if (bigInt.compareTo(java.math.BigInteger.valueOf(Integer.MAX_VALUE)) > 0
                || bigInt.compareTo(java.math.BigInteger.ZERO) < 0) {
            throw new CertificateParsingException("INTEGER out of bounds");
        }
        return bigInt.intValue();
    }

    private static long bigIntegerToLong(java.math.BigInteger bigInt) throws CertificateParsingException {
        if (bigInt.compareTo(java.math.BigInteger.valueOf(Long.MAX_VALUE)) > 0
                || bigInt.compareTo(java.math.BigInteger.ZERO) < 0) {
            throw new CertificateParsingException("INTEGER out of bounds");
        }
        return bigInt.longValue();
    }
}
