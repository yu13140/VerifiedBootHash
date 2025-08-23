package io.github.xtrlumen.vbmeta

import android.app.Activity
import android.os.Bundle
import android.view.ViewGroup.LayoutParams
import android.widget.FrameLayout
import android.widget.TextView
import io.github.xtrlumen.vbmeta.attestation.Attestation
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.spec.ECGenParameterSpec
import java.io.File
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = FrameLayout(this)
        val tv = TextView(this)
        tv.layoutParams = FrameLayout.LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT)
        tv.isSingleLine = true
        tv.text = ""
        tv.typeface = android.graphics.Typeface.MONOSPACE
        tv.textSize = 14f
        val padding = (16 * resources.displayMetrics.density).toInt()
        root.setPadding(padding, padding, padding, padding)
        root.addView(tv)
        setContentView(root)

        Thread {
            val alias = "KeyAttestation"
            val genErr = generateKeyWithAttestation(alias, useStrongBox = false)
            if (genErr != null) {
                runOnUiThread { tv.text = "(error: gen key)" }
            } else {
                val certBytes = getLeafCertificateBytes(alias)
                if (certBytes == null) {
                    runOnUiThread { tv.text = "(error: no cert)" }
                } else {
                    val cf = CertificateFactory.getInstance("X.509")
                    val cert = cf.generateCertificate(ByteArrayInputStream(certBytes)) as java.security.cert.X509Certificate
                    val att = try { Attestation.loadFromCertificate(cert) } catch (_: Exception) { null }
                    val hash = att?.rootOfTrust?.verifiedBootHash
                    val hexStr = if (hash != null) hash.joinToString(separator = "") { b ->
                        val v = b.toInt() and 0xFF
                        ((v ushr 4).toString(16) + (v and 0x0F).toString(16))
                    } else "(empty)"
                    runOnUiThread {
                        tv.text = hexStr
                    }
                    try {
                        val file = File("/data/data/io.github.xtrlumen.vbmeta/verifiedboothash.txt")
                        file.writeText(hexStr)
                    } catch (_: Exception) {
                    }
                    try {
                        val cacheDir = File("/data/data/io.github.xtrlumen.vbmeta/cache")
                        if (cacheDir.exists()) cacheDir.deleteRecursively()
                        val codeCacheDir = File("/data/data/io.github.xtrlumen.vbmeta/code_cache")
                        if (codeCacheDir.exists()) codeCacheDir.deleteRecursively()
                    } catch (_: Exception) {
                    }
                }
            }
        }.start()
    }

    private fun getLeafCertificateBytes(alias: String): ByteArray? {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val cert = ks.getCertificate(alias) as? X509Certificate ?: return null
            cert.encoded
        } catch (_: Exception) {
            return null
        }
    }

    private fun generateKeyWithAttestation(alias: String, useStrongBox: Boolean): Exception? {
        return try {
            // Clean existing
            runCatching {
                val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                if (ks.containsAlias(alias)) ks.deleteEntry(alias)
            }

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val challenge = (alias + ":challenge").toByteArray()
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setAttestationChallenge(challenge)
                .setUserAuthenticationRequired(false)

            if (useStrongBox) {
                runCatching { builder.setIsStrongBoxBacked(true) }
            }

            kpg.initialize(builder.build())
            kpg.generateKeyPair()
            null
        } catch (e: Exception) {
            e
        }
    }
}
