package com.yu13140.verifiedboothash

import org.bouncycastle.asn1.*
import java.io.ByteArrayInputStream
import java.security.cert.X509Certificate

object AttestationParser {
    private const val ASN1_OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val KM_TAG_ROOT_OF_TRUST = 704
    private const val KEYMASTER_TAG_TYPE_MASK = 0x0FFFFFFF

    fun parseVerifiedBootHash(cert: X509Certificate): ByteArray? {
        try {
            val extensionValue = cert.getExtensionValue(ASN1_OID) ?: return null

            val asn1InputStream = ASN1InputStream(ByteArrayInputStream(extensionValue))
            val asn1Primitive = asn1InputStream.readObject()

            val octetString = if (asn1Primitive is ASN1OctetString) {
                ASN1InputStream(ByteArrayInputStream(asn1Primitive.octets)).readObject()
            } else {
                asn1Primitive
            }

            if (octetString !is ASN1Sequence) return null

            val teeEnforced = if (octetString.size() > 7) {
                octetString.getObjectAt(7) as? ASN1Sequence
            } else {
                null
            } ?: return null

            val rootOfTrust = findRootOfTrust(teeEnforced) ?: return null

            if (rootOfTrust.size() >= 4) {
                val verifiedBootHashElement = rootOfTrust.getObjectAt(3)
                return extractBytesFromAsn1(verifiedBootHashElement)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    private fun findRootOfTrust(authList: ASN1Sequence): ASN1Sequence? {
        for (i in 0 until authList.size()) {
            val element = authList.getObjectAt(i)
            if (element is ASN1TaggedObject) {
                val tagNo = element.tagNo
                if (tagNo == (KM_TAG_ROOT_OF_TRUST and KEYMASTER_TAG_TYPE_MASK)) {
                    return element.baseObject as? ASN1Sequence
                }
            }
        }
        return null
    }

    private fun extractBytesFromAsn1(asn1Element: ASN1Encodable): ByteArray? {
        return when (asn1Element) {
            is ASN1OctetString -> asn1Element.octets
            is DEROctetString -> asn1Element.octets
            else -> null
        }
    }
}