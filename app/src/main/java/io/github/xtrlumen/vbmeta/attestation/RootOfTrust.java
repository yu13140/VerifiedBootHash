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

import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.security.cert.CertificateParsingException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

public class RootOfTrust {
    private static final int VERIFIED_BOOT_KEY_INDEX = 0;
    private static final int DEVICE_LOCKED_INDEX = 1;
    private static final int VERIFIED_BOOT_STATE_INDEX = 2;
    private static final int VERIFIED_BOOT_HASH_INDEX = 3;

    public static final int KM_VERIFIED_BOOT_VERIFIED = 0;
    public static final int KM_VERIFIED_BOOT_SELF_SIGNED = 1;
    public static final int KM_VERIFIED_BOOT_UNVERIFIED = 2;
    public static final int KM_VERIFIED_BOOT_FAILED = 3;

    private final byte[] verifiedBootKey;
    private final boolean deviceLocked;
    private final int verifiedBootState;
    private final byte[] verifiedBootHash;

    public RootOfTrust(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException("Expected sequence for root of trust, found "
                    + asn1Encodable.getClass().getName());
        }

        verifiedBootKey =
                Asn1Utils.getByteArrayFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_KEY_INDEX));
        deviceLocked = Asn1Utils.getBooleanFromAsn1(sequence.getObjectAt(DEVICE_LOCKED_INDEX));
        verifiedBootState =
                Asn1Utils.getIntegerFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_STATE_INDEX));
        if (sequence.size() == 3) verifiedBootHash = null;
        else verifiedBootHash =
                Asn1Utils.getByteArrayFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_HASH_INDEX));
    }

    RootOfTrust(byte[] verifiedBootKey, boolean deviceLocked,
                int verifiedBootState, byte[] verifiedBootHash) {
        this.verifiedBootKey = verifiedBootKey;
        this.deviceLocked = deviceLocked;
        this.verifiedBootState = verifiedBootState;
        this.verifiedBootHash = verifiedBootHash;
    }

    public static String verifiedBootStateToString(int verifiedBootState) {
        switch (verifiedBootState) {
            case KM_VERIFIED_BOOT_VERIFIED:
                return "Verified";
            case KM_VERIFIED_BOOT_SELF_SIGNED:
                return "Self-signed";
            case KM_VERIFIED_BOOT_UNVERIFIED:
                return "Unverified";
            case KM_VERIFIED_BOOT_FAILED:
                return "Failed";
            default:
                return "Unknown (" + verifiedBootState + ")";
        }
    }

    public byte[] getVerifiedBootKey() {
        return verifiedBootKey;
    }

    public boolean isDeviceLocked() {
        return deviceLocked;
    }

    public int getVerifiedBootState() {
        return verifiedBootState;
    }

    public byte[] getVerifiedBootHash() {
        return verifiedBootHash;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder()
                .append("verifiedBootKey: ")
                .append(toHexLower(verifiedBootKey))
                .append("\ndeviceLocked: ")
                .append(deviceLocked)
                .append("\nverifiedBootState: ")
                .append(verifiedBootStateToString(verifiedBootState));
        if (verifiedBootHash != null) {
            sb.append("\nverifiedBootHash: ")
                    .append(toHexLower(verifiedBootHash));
        }
        return sb.toString();
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

    public static class Builder {
        private byte[] verifiedBootKey;
        private boolean deviceLocked = false;
        private int verifiedBootState = -1;
        private byte[] verifiedBootHash;

        public Builder setVerifiedBootKey(byte[] verifiedBootKey) {
            this.verifiedBootKey = verifiedBootKey;
            return this;
        }

        public Builder setDeviceLocked(boolean deviceLocked) {
            this.deviceLocked = deviceLocked;
            return this;
        }

        public Builder setVerifiedBootState(int verifiedBootState) {
            this.verifiedBootState = verifiedBootState;
            return this;
        }

        public Builder setVerifiedBootHash(byte[] verifiedBootHash) {
            this.verifiedBootHash = verifiedBootHash;
            return this;
        }

        public RootOfTrust build() {
            return new RootOfTrust(verifiedBootKey, deviceLocked,
                    verifiedBootState, verifiedBootHash);
        }
    }
}

// Merged: AuthorizationList (was in separate file AuthorizationList.java)
class AuthorizationList {
    // Algorithm values.
    public static final int KM_ALGORITHM_RSA = 1;
    public static final int KM_ALGORITHM_EC = 3;
    public static final int KM_ALGORITHM_AES = 32;
    public static final int KM_ALGORITHM_3DES = 33;
    public static final int KM_ALGORITHM_HMAC = 128;

    // EC Curves
    public static final int KM_EC_CURVE_P224 = 0;
    public static final int KM_EC_CURVE_P256 = 1;
    public static final int KM_EC_CURVE_P384 = 2;
    public static final int KM_EC_CURVE_P521 = 3;
    public static final int KM_EC_CURVE_25519 = 4;

    // Padding modes.
    public static final int KM_PAD_NONE = 1;
    public static final int KM_PAD_RSA_OAEP = 2;
    public static final int KM_PAD_RSA_PSS = 3;
    public static final int KM_PAD_RSA_PKCS1_1_5_ENCRYPT = 4;
    public static final int KM_PAD_RSA_PKCS1_1_5_SIGN = 5;
    public static final int KM_PAD_PKCS7 = 64;

    // Digest modes.
    public static final int KM_DIGEST_NONE = 0;
    public static final int KM_DIGEST_MD5 = 1;
    public static final int KM_DIGEST_SHA1 = 2;
    public static final int KM_DIGEST_SHA_2_224 = 3;
    public static final int KM_DIGEST_SHA_2_256 = 4;
    public static final int KM_DIGEST_SHA_2_384 = 5;
    public static final int KM_DIGEST_SHA_2_512 = 6;

    // Key origins.
    public static final int KM_ORIGIN_GENERATED = 0;
    public static final int KM_ORIGIN_DERIVED = 1;
    public static final int KM_ORIGIN_IMPORTED = 2;
    public static final int KM_ORIGIN_UNKNOWN = 3;
    public static final int KM_ORIGIN_SECURELY_IMPORTED = 4;

    // Operation Purposes.
    public static final int KM_PURPOSE_ENCRYPT = 0;
    public static final int KM_PURPOSE_DECRYPT = 1;
    public static final int KM_PURPOSE_SIGN = 2;
    public static final int KM_PURPOSE_VERIFY = 3;
    public static final int KM_PURPOSE_WRAP = 5;
    public static final int KM_PURPOSE_AGREE_KEY = 6;
    public static final int KM_PURPOSE_ATTEST_KEY = 7;

    // User authenticators.
    public static final int HW_AUTH_PASSWORD = 1 << 0;
    public static final int HW_AUTH_BIOMETRIC = 1 << 1;

    // Keymaster tag classes
    public static final int KM_ENUM = 1 << 28;
    public static final int KM_ENUM_REP = 2 << 28;
    public static final int KM_UINT = 3 << 28;
    public static final int KM_UINT_REP = 4 << 28;
    public static final int KM_ULONG = 5 << 28;
    public static final int KM_DATE = 6 << 28;
    public static final int KM_BOOL = 7 << 28;
    public static final int KM_BYTES = 9 << 28;
    public static final int KM_ULONG_REP = 10 << 28;

    // Tag class removal mask
    public static final int KEYMASTER_TAG_TYPE_MASK = 0x0FFFFFFF;

    // Keymaster tags
    public static final int KM_TAG_PURPOSE = KM_ENUM_REP | 1;
    public static final int KM_TAG_ALGORITHM = KM_ENUM | 2;
    public static final int KM_TAG_KEY_SIZE = KM_UINT | 3;
    public static final int KM_TAG_BLOCK_MODE = KM_ENUM_REP | 4;
    public static final int KM_TAG_DIGEST = KM_ENUM_REP | 5;
    public static final int KM_TAG_PADDING = KM_ENUM_REP | 6;
    public static final int KM_TAG_CALLER_NONCE = KM_BOOL | 7;
    public static final int KM_TAG_MIN_MAC_LENGTH = KM_UINT | 8;
    public static final int KM_TAG_KDF = KM_ENUM_REP | 9;
    public static final int KM_TAG_EC_CURVE = KM_ENUM | 10;
    public static final int KM_TAG_RSA_PUBLIC_EXPONENT = KM_ULONG | 200;
    public static final int KM_TAG_RSA_OAEP_MGF_DIGEST = KM_ENUM_REP | 203;
    public static final int KM_TAG_ROLLBACK_RESISTANCE = KM_BOOL | 303;
    public static final int KM_TAG_EARLY_BOOT_ONLY = KM_BOOL | 305;
    public static final int KM_TAG_ACTIVE_DATETIME = KM_DATE | 400;
    public static final int KM_TAG_ORIGINATION_EXPIRE_DATETIME = KM_DATE | 401;
    public static final int KM_TAG_USAGE_EXPIRE_DATETIME = KM_DATE | 402;
    public static final int KM_TAG_USAGE_COUNT_LIMIT = KM_UINT | 405;
    public static final int KM_TAG_NO_AUTH_REQUIRED = KM_BOOL | 503;
    public static final int KM_TAG_USER_AUTH_TYPE = KM_ENUM | 504;
    public static final int KM_TAG_AUTH_TIMEOUT = KM_UINT | 505;
    public static final int KM_TAG_ALLOW_WHILE_ON_BODY = KM_BOOL | 506;
    public static final int KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = KM_BOOL | 507;
    public static final int KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = KM_BOOL | 508;
    public static final int KM_TAG_UNLOCKED_DEVICE_REQUIRED = KM_BOOL | 509;
    public static final int KM_TAG_ALL_APPLICATIONS = KM_BOOL | 600;
    public static final int KM_TAG_APPLICATION_ID = KM_BYTES | 601;
    public static final int KM_TAG_CREATION_DATETIME = KM_DATE | 701;
    public static final int KM_TAG_ORIGIN = KM_ENUM | 702;
    public static final int KM_TAG_ROLLBACK_RESISTANT = KM_BOOL | 703;
    public static final int KM_TAG_ROOT_OF_TRUST = KM_BYTES | 704;
    public static final int KM_TAG_OS_VERSION = KM_UINT | 705;
    public static final int KM_TAG_OS_PATCHLEVEL = KM_UINT | 706;
    public static final int KM_TAG_ATTESTATION_APPLICATION_ID = KM_BYTES | 709;
    public static final int KM_TAG_ATTESTATION_ID_BRAND = KM_BYTES | 710;
    public static final int KM_TAG_ATTESTATION_ID_DEVICE = KM_BYTES | 711;
    public static final int KM_TAG_ATTESTATION_ID_PRODUCT = KM_BYTES | 712;
    public static final int KM_TAG_ATTESTATION_ID_SERIAL = KM_BYTES | 713;
    public static final int KM_TAG_ATTESTATION_ID_IMEI = KM_BYTES | 714;
    public static final int KM_TAG_ATTESTATION_ID_MEID = KM_BYTES | 715;
    public static final int KM_TAG_ATTESTATION_ID_MANUFACTURER = KM_BYTES | 716;
    public static final int KM_TAG_ATTESTATION_ID_MODEL = KM_BYTES | 717;
    public static final int KM_TAG_VENDOR_PATCHLEVEL = KM_UINT | 718;
    public static final int KM_TAG_BOOT_PATCHLEVEL = KM_UINT | 719;
    public static final int KM_TAG_DEVICE_UNIQUE_ATTESTATION = KM_BOOL | 720;
    public static final int KM_TAG_IDENTITY_CREDENTIAL_KEY = KM_BOOL | 721;
    public static final int KM_TAG_ATTESTATION_ID_SECOND_IMEI = KM_BYTES | 723;
    public static final int KM_TAG_MODULE_HASH = KM_BYTES | 724;

    // Map for converting padding values to strings
    private static final java.util.Map<Integer, String> paddingMap = new HashMap<>();
    static {
        paddingMap.put(KM_PAD_NONE, KeyProperties.ENCRYPTION_PADDING_NONE);
        paddingMap.put(KM_PAD_RSA_OAEP, KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
        paddingMap.put(KM_PAD_RSA_PSS, KeyProperties.SIGNATURE_PADDING_RSA_PSS);
        paddingMap.put(KM_PAD_RSA_PKCS1_1_5_ENCRYPT, KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
        paddingMap.put(KM_PAD_RSA_PKCS1_1_5_SIGN, KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);
        paddingMap.put(KM_PAD_PKCS7, KeyProperties.ENCRYPTION_PADDING_PKCS7);
    }

    // Map for converting digest values to strings
    private static final java.util.Map<Integer, String> digestMap = new HashMap<>();
    static {
        digestMap.put(KM_DIGEST_NONE, KeyProperties.DIGEST_NONE);
        digestMap.put(KM_DIGEST_MD5, KeyProperties.DIGEST_MD5);
        digestMap.put(KM_DIGEST_SHA1, KeyProperties.DIGEST_SHA1);
        digestMap.put(KM_DIGEST_SHA_2_224, KeyProperties.DIGEST_SHA224);
        digestMap.put(KM_DIGEST_SHA_2_256, KeyProperties.DIGEST_SHA256);
        digestMap.put(KM_DIGEST_SHA_2_384, KeyProperties.DIGEST_SHA384);
        digestMap.put(KM_DIGEST_SHA_2_512, KeyProperties.DIGEST_SHA512);
    }

    // Map for converting purpose values to strings
    private static final java.util.Map<Integer, String> purposeMap = new HashMap<>();
    static {
        purposeMap.put(KM_PURPOSE_DECRYPT, "DECRYPT");
        purposeMap.put(KM_PURPOSE_ENCRYPT, "ENCRYPT");
        purposeMap.put(KM_PURPOSE_SIGN, "SIGN");
        purposeMap.put(KM_PURPOSE_VERIFY, "VERIFY");
        purposeMap.put(KM_PURPOSE_WRAP, "WRAP");
        purposeMap.put(KM_PURPOSE_AGREE_KEY, "AGREE KEY");
        purposeMap.put(KM_PURPOSE_ATTEST_KEY, "ATTEST KEY");
    }

    private Integer securityLevel;
    private Set<Integer> purposes;
    private Integer algorithm;
    private Integer keySize;
    private Set<Integer> digests;
    private Set<Integer> paddingModes;
    private Integer ecCurve;
    private Long rsaPublicExponent;
    private Set<Integer> mgfDigests;
    private Boolean rollbackResistance;
    private Boolean earlyBootOnly;
    private Date activeDateTime;
    private Date originationExpireDateTime;
    private Date usageExpireDateTime;
    private Integer usageCountLimit;
    private Boolean noAuthRequired;
    private Integer userAuthType;
    private Integer authTimeout;
    private Boolean allowWhileOnBody;
    private Boolean trustedUserPresenceReq;
    private Boolean trustedConfirmationReq;
    private Boolean unlockedDeviceReq;
    private Boolean allApplications;
    private String applicationId;
    private Date creationDateTime;
    private Integer origin;
    private Boolean rollbackResistant;
    private RootOfTrust rootOfTrust;
    private Integer osVersion;
    private Integer osPatchLevel;
    // Removed attestationApplicationId to reduce code size
    private String brand;
    private String device;
    private String product;
    private String serialNumber;
    private String imei;
    private String meid;
    private String manufacturer;
    private String model;
    private Integer vendorPatchLevel;
    private Integer bootPatchLevel;
    private Boolean deviceUniqueAttestation;
    private Boolean identityCredentialKey;
    private String secondImei;
    private byte[] moduleHash;

    public AuthorizationList(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException("Expected sequence for authorization list, found "
                    + asn1Encodable.getClass().getName());
        }
        for (var entry : sequence) {
            if (!(entry instanceof ASN1TaggedObject taggedObject)) {
                throw new CertificateParsingException(
                        "Expected tagged object, found " + entry.getClass().getName());
            }
            int tag = taggedObject.getTagNo();
            var value = taggedObject.getBaseObject().toASN1Primitive();
            Log.v("KeyAttestation", "Parsing tag: [" + tag + "], value: [" + value + "]");
            switch (tag) {
                default:
                    throw new CertificateParsingException("Unknown tag " + tag + " found");

                case KM_TAG_PURPOSE & KEYMASTER_TAG_TYPE_MASK:
                    purposes = Asn1Utils.getIntegersFromAsn1Set(value);
                    break;
                case KM_TAG_ALGORITHM & KEYMASTER_TAG_TYPE_MASK:
                    algorithm = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_KEY_SIZE & KEYMASTER_TAG_TYPE_MASK:
                    keySize = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_DIGEST & KEYMASTER_TAG_TYPE_MASK:
                    digests = Asn1Utils.getIntegersFromAsn1Set(value);
                    break;
                case KM_TAG_PADDING & KEYMASTER_TAG_TYPE_MASK:
                    paddingModes = Asn1Utils.getIntegersFromAsn1Set(value);
                    break;
                case KM_TAG_EC_CURVE & KEYMASTER_TAG_TYPE_MASK:
                    ecCurve = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_RSA_PUBLIC_EXPONENT & KEYMASTER_TAG_TYPE_MASK:
                    rsaPublicExponent = Asn1Utils.getLongFromAsn1(value);
                    break;
                case KM_TAG_RSA_OAEP_MGF_DIGEST & KEYMASTER_TAG_TYPE_MASK:
                    mgfDigests = Asn1Utils.getIntegersFromAsn1Set(value);
                    break;
                case KM_TAG_ROLLBACK_RESISTANCE & KEYMASTER_TAG_TYPE_MASK:
                    rollbackResistance = true;
                    break;
                case KM_TAG_EARLY_BOOT_ONLY & KEYMASTER_TAG_TYPE_MASK:
                    earlyBootOnly = true;
                    break;
                case KM_TAG_ACTIVE_DATETIME & KEYMASTER_TAG_TYPE_MASK:
                    activeDateTime = Asn1Utils.getDateFromAsn1(value);
                    break;
                case KM_TAG_ORIGINATION_EXPIRE_DATETIME & KEYMASTER_TAG_TYPE_MASK:
                    originationExpireDateTime = Asn1Utils.getDateFromAsn1(value);
                    break;
                case KM_TAG_USAGE_EXPIRE_DATETIME & KEYMASTER_TAG_TYPE_MASK:
                    usageExpireDateTime = Asn1Utils.getDateFromAsn1(value);
                    break;
                case KM_TAG_USAGE_COUNT_LIMIT & KEYMASTER_TAG_TYPE_MASK:
                    usageCountLimit = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_NO_AUTH_REQUIRED & KEYMASTER_TAG_TYPE_MASK:
                    noAuthRequired = true;
                    break;
                case KM_TAG_USER_AUTH_TYPE & KEYMASTER_TAG_TYPE_MASK:
                    userAuthType = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_AUTH_TIMEOUT & KEYMASTER_TAG_TYPE_MASK:
                    authTimeout = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_ALLOW_WHILE_ON_BODY & KEYMASTER_TAG_TYPE_MASK:
                    allowWhileOnBody = true;
                    break;
                case KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED & KEYMASTER_TAG_TYPE_MASK:
                    trustedUserPresenceReq = true;
                    break;
                case KM_TAG_TRUSTED_CONFIRMATION_REQUIRED & KEYMASTER_TAG_TYPE_MASK:
                    trustedConfirmationReq = true;
                    break;
                case KM_TAG_UNLOCKED_DEVICE_REQUIRED & KEYMASTER_TAG_TYPE_MASK:
                    unlockedDeviceReq = true;
                    break;
                case KM_TAG_ALL_APPLICATIONS & KEYMASTER_TAG_TYPE_MASK:
                    allApplications = true;
                    break;
                case KM_TAG_APPLICATION_ID & KEYMASTER_TAG_TYPE_MASK:
                    applicationId = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_CREATION_DATETIME & KEYMASTER_TAG_TYPE_MASK:
                    creationDateTime = Asn1Utils.getDateFromAsn1(value);
                    break;
                case KM_TAG_ORIGIN & KEYMASTER_TAG_TYPE_MASK:
                    origin = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_ROLLBACK_RESISTANT & KEYMASTER_TAG_TYPE_MASK:
                    rollbackResistant = true;
                    break;
                case KM_TAG_ROOT_OF_TRUST & KEYMASTER_TAG_TYPE_MASK:
                    rootOfTrust = new RootOfTrust(value);
                    break;
                case KM_TAG_OS_VERSION & KEYMASTER_TAG_TYPE_MASK:
                    osVersion = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_OS_PATCHLEVEL & KEYMASTER_TAG_TYPE_MASK:
                    osPatchLevel = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_ATTESTATION_APPLICATION_ID & KEYMASTER_TAG_TYPE_MASK:
                    // Skip parsing AttestationApplicationId
                    break;
                case KM_TAG_ATTESTATION_ID_BRAND & KEYMASTER_TAG_TYPE_MASK:
                    brand = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_ATTESTATION_ID_DEVICE & KEYMASTER_TAG_TYPE_MASK:
                    device = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_ATTESTATION_ID_PRODUCT & KEYMASTER_TAG_TYPE_MASK:
                    product = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_ATTESTATION_ID_SERIAL & KEYMASTER_TAG_TYPE_MASK:
                    serialNumber = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_ATTESTATION_ID_IMEI & KEYMASTER_TAG_TYPE_MASK:
                    imei = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_ATTESTATION_ID_MEID & KEYMASTER_TAG_TYPE_MASK:
                    meid = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_ATTESTATION_ID_MANUFACTURER & KEYMASTER_TAG_TYPE_MASK:
                    manufacturer = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_ATTESTATION_ID_MODEL & KEYMASTER_TAG_TYPE_MASK:
                    model = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_VENDOR_PATCHLEVEL & KEYMASTER_TAG_TYPE_MASK:
                    vendorPatchLevel = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_BOOT_PATCHLEVEL & KEYMASTER_TAG_TYPE_MASK:
                    bootPatchLevel = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_DEVICE_UNIQUE_ATTESTATION & KEYMASTER_TAG_TYPE_MASK:
                    deviceUniqueAttestation = true;
                    break;
                case KM_TAG_IDENTITY_CREDENTIAL_KEY & KEYMASTER_TAG_TYPE_MASK:
                    identityCredentialKey = true;
                    break;
                case KM_TAG_ATTESTATION_ID_SECOND_IMEI & KEYMASTER_TAG_TYPE_MASK:
                    secondImei = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
                    break;
                case KM_TAG_MODULE_HASH & KEYMASTER_TAG_TYPE_MASK:
                    moduleHash = Asn1Utils.getByteArrayFromAsn1(value);
                    break;
            }
        }

    }

    private static String joinStrings(Collection<String> collection) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String s : collection) {
            if (!first) sb.append(", ");
            sb.append(s);
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    public static String formatDate(Date date) {
        return DateFormat.getDateTimeInstance().format(date);
    }

    public static String paddingModesToString(final Set<Integer> paddingModes) {
        List<String> list = new ArrayList<>();
        for (Integer v : paddingModes) {
            String s = paddingMap.get(v);
            list.add(s != null ? s : "Unknown");
        }
        return joinStrings(list);
    }

    public static String digestsToString(Set<Integer> digests) {
        List<String> list = new ArrayList<>();
        for (Integer v : digests) {
            String s = digestMap.get(v);
            list.add(s != null ? s : "Unknown");
        }
        return joinStrings(list);
    }

    public static String purposesToString(Set<Integer> purposes) {
        List<String> list = new ArrayList<>();
        for (Integer v : purposes) {
            String s = purposeMap.get(v);
            list.add(s != null ? s : "Unknown");
        }
        return joinStrings(list);
    }

    public static String algorithmToString(int algorithm) {
        return switch (algorithm) {
            case KM_ALGORITHM_RSA -> KeyProperties.KEY_ALGORITHM_RSA;
            case KM_ALGORITHM_EC -> KeyProperties.KEY_ALGORITHM_EC;
            case KM_ALGORITHM_AES -> KeyProperties.KEY_ALGORITHM_AES;
            case KM_ALGORITHM_3DES -> KeyProperties.KEY_ALGORITHM_3DES;
            case KM_ALGORITHM_HMAC -> "HMAC";
            default -> "Unknown (" + algorithm + ")";
        };
    }

    public static String userAuthTypeToString(int userAuthType) {
        List<String> types = new ArrayList<>();
        if ((userAuthType & HW_AUTH_BIOMETRIC) != 0)
            types.add("Biometric");
        if ((userAuthType & HW_AUTH_PASSWORD) != 0)
            types.add("Password");
        return joinStrings(types);
    }

    public static String originToString(int origin) {
        return switch (origin) {
            case KM_ORIGIN_GENERATED -> "Generated";
            case KM_ORIGIN_DERIVED -> "Derived";
            case KM_ORIGIN_IMPORTED -> "Imported";
            case KM_ORIGIN_UNKNOWN -> "Unknown (KM0)";
            case KM_ORIGIN_SECURELY_IMPORTED -> "Securely Imported";
            default -> "Unknown (" + origin + ")";
        };
    }

    public static String ecCurveAsString(Integer ecCurve) {
        return switch (ecCurve) {
            case KM_EC_CURVE_P224 -> "secp224r1";
            case KM_EC_CURVE_P256 -> "secp256r1";
            case KM_EC_CURVE_P384 -> "secp384r1";
            case KM_EC_CURVE_P521 -> "secp521r1";
            case KM_EC_CURVE_25519 -> "CURVE_25519";
            default -> "unknown (" + ecCurve + ")";
        };
    }

    public Integer getSecurityLevel() { return securityLevel; }
    public Set<Integer> getPurposes() { return purposes; }
    public Integer getAlgorithm() { return algorithm; }
    public Integer getKeySize() { return keySize; }
    public Set<Integer> getDigests() { return digests; }
    public Set<Integer> getPaddingModes() { return paddingModes; }
    public Integer getEcCurve() { return ecCurve; }
    public Long getRsaPublicExponent() { return rsaPublicExponent; }
    public Set<Integer> getMgfDigests() { return mgfDigests; }
    public Boolean getRollbackResistance() { return rollbackResistance; }
    public Boolean getEarlyBootOnly() { return earlyBootOnly; }
    public Date getActiveDateTime() { return activeDateTime; }
    public Date getOriginationExpireDateTime() { return originationExpireDateTime; }
    public Date getUsageExpireDateTime() { return usageExpireDateTime; }
    public Integer getUsageCountLimit() { return usageCountLimit; }
    public Boolean getNoAuthRequired() { return noAuthRequired; }
    public Integer getUserAuthType() { return userAuthType; }
    public Integer getAuthTimeout() { return authTimeout; }
    public Boolean getAllowWhileOnBody() { return allowWhileOnBody; }
    public Boolean getTrustedUserPresenceReq() { return trustedUserPresenceReq; }
    public Boolean getTrustedConfirmationReq() { return trustedConfirmationReq; }
    public Boolean getUnlockedDeviceReq() { return unlockedDeviceReq; }
    public Boolean getAllApplications() { return allApplications; }
    public String getApplicationId() { return applicationId; }
    public Date getCreationDateTime() { return creationDateTime; }
    public Integer getOrigin() { return origin; }
    public Boolean getRollbackResistant() { return rollbackResistant; }
    public RootOfTrust getRootOfTrust() { return rootOfTrust; }
    public Integer getOsVersion() { return osVersion; }
    public Integer getOsPatchLevel() { return osPatchLevel; }
    public String getBrand() { return brand; }
    public String getDevice() { return device; }
    public String getProduct() { return product; }
    public String getSerialNumber() { return serialNumber; }
    public String getImei() { return imei; }
    public String getMeid() { return meid; }
    public String getManufacturer() { return manufacturer; }
    public String getModel() { return model; }
    public Integer getVendorPatchLevel() { return vendorPatchLevel; }
    public Integer getBootPatchLevel() { return bootPatchLevel; }
    public Boolean getDeviceUniqueAttestation() { return deviceUniqueAttestation; }
    public Boolean getIdentityCredentialKey() { return identityCredentialKey; }
    public String getSecondImei() { return secondImei; }
    public byte[] getModuleHash() { return moduleHash; }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();

        if (algorithm != null) { s.append("\nAlgorithm: ").append(algorithmToString(algorithm)); }
        if (keySize != null) { s.append("\nKeySize: ").append(keySize); }
        if (purposes != null && !purposes.isEmpty()) { s.append("\nPurposes: ").append(purposesToString(purposes)); }
        if (digests != null && !digests.isEmpty()) { s.append("\nDigests: ").append(digestsToString(digests)); }
        if (paddingModes != null && !paddingModes.isEmpty()) { s.append("\nPadding modes: ").append(paddingModesToString(paddingModes)); }
        if (ecCurve != null) { s.append("\nEC Curve: ").append(ecCurveAsString(ecCurve)); }
        if (rsaPublicExponent != null) { s.append("\nRSA exponent: ").append(rsaPublicExponent); }
        if (mgfDigests != null && !mgfDigests.isEmpty()) { s.append("\nRsa Oaep Mgf Digest: ").append(digestsToString(mgfDigests)); }
        if (earlyBootOnly != null) { s.append("\nEarly boot only"); }
        if (activeDateTime != null) { s.append("\nActive: ").append(formatDate(activeDateTime)); }
        if (originationExpireDateTime != null) { s.append("\nOrigination expire: ").append(formatDate(originationExpireDateTime)); }
        if (usageExpireDateTime != null) { s.append("\nUsage expire: ").append(formatDate(usageExpireDateTime)); }
        if (usageCountLimit != null) { s.append("\nUsage count limit: ").append(usageCountLimit); }
        if (noAuthRequired != null) { s.append("\nNo Auth Required"); }
        if (userAuthType != null) { s.append("\nAuth types: ").append(userAuthTypeToString(userAuthType)); }
        if (authTimeout != null) { s.append("\nAuth timeout: ").append(authTimeout); }
        if (allowWhileOnBody != null) { s.append("\nAllow While On Body"); }
        if (allApplications != null) { s.append("\nAll Applications"); }
        if (applicationId != null) { s.append("\nApplication ID: ").append(applicationId); }
        if (creationDateTime != null) { s.append("\nCreated: ").append(formatDate(creationDateTime)); }
        if (origin != null) { s.append("\nOrigin: ").append(originToString(origin)); }
        if (rollbackResistant != null) { s.append("\nRollback resistant"); }
        if (rollbackResistance != null) { s.append("\nRollback resistance"); }
        if (rootOfTrust != null) { s.append("\nRoot of Trust:\n"); s.append(rootOfTrust); }
        if (osVersion != null) { s.append("\nOS Version: ").append(osVersion); }
        if (osPatchLevel != null) { s.append("\nOS Patchlevel: ").append(osPatchLevel); }
        if (vendorPatchLevel != null) { s.append("\nVendor Patchlevel: ").append(vendorPatchLevel); }
        if (bootPatchLevel != null) { s.append("\nBoot Patchlevel: ").append(bootPatchLevel); }
        if (trustedUserPresenceReq != null) { s.append("\nUser presence required"); }
        if (trustedConfirmationReq != null) { s.append("\nConfirmation required"); }
        if (unlockedDeviceReq != null) { s.append("\nUnlocked Device Required"); }
        if (deviceUniqueAttestation != null) { s.append("\nDevice unique attestation"); }
        if (identityCredentialKey != null) { s.append("\nIdentity Credential Key"); }
        if (brand != null) { s.append("\nBrand: ").append(brand); }
        if (device != null) { s.append("\nDevice type: ").append(device); }
        if (product != null) { s.append("\nProduct: ").append(product); }
        if (serialNumber != null) { s.append("\nSerial: ").append(serialNumber); }
        if (imei != null) { s.append("\nIMEI: ").append(imei); }
        if (secondImei != null) { s.append("\nSecond IMEI:").append(secondImei); }
        if (meid != null) { s.append("\nMEID: ").append(meid); }
        if (manufacturer != null) { s.append("\nManufacturer: ").append(manufacturer); }
        if (model != null) { s.append("\nModel: ").append(model); }
        if (moduleHash != null) { s.append("\nModule Hash: ").append(toHexLower(moduleHash)); }
        return s.toString();
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
