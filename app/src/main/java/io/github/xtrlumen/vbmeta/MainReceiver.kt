package io.github.xtrlumen.vbmeta

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.xtrlumen.vbmeta.attestation.Attestation
import java.io.ByteArrayInputStream
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

class MainReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        val finished = AtomicBoolean(false)

        Thread {
            try {
                val alias = "KeyAttestation"
                generateKeyWithAttestation(alias, useStrongBox = false) ?: run {
                    val certBytes = getLeafCertificateBytes(alias)
                    if (certBytes != null) {
                        val cf = CertificateFactory.getInstance("X.509")
                        val cert = cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
                        val att = try { Attestation.loadFromCertificate(cert) } catch (_: Exception) { null }
                        val hash = att?.rootOfTrust?.verifiedBootHash
                        val hexStr = if (hash != null) hash.joinToString("") { b ->
                            val v = b.toInt() and 0xFF
                            ((v ushr 4).toString(16) + (v and 0x0F).toString(16))
                        } else "(empty)"
                        try {
                            val appDir = context.dataDir
                            File(appDir, "verifiedboothash.txt").writeText(hexStr)
                            context.cacheDir.takeIf { it.exists() }?.deleteRecursively()
                            context.codeCacheDir.takeIf { it.exists() }?.deleteRecursively()
                        } catch (_: Exception) { }
                    }
                }
            } catch (_: Exception) { }
            finally {
                if (finished.compareAndSet(false, true)) {
                    try { pending.finish() } catch (_: Exception) { }
                }
            }
        }.start()

        Thread {
            try { Thread.sleep(5000) } catch (_: InterruptedException) { }
            if (finished.compareAndSet(false, true)) {
                try { pending.finish() } catch (_: Exception) { }
            }
        }.start()
    }

    private fun getLeafCertificateBytes(alias: String): ByteArray? {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val cert = ks.getCertificate(alias) as? X509Certificate ?: return null
            cert.encoded
        } catch (_: Exception) { null }
    }

    private fun generateKeyWithAttestation(alias: String, useStrongBox: Boolean): Exception? {
        return try {
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
            if (useStrongBox) runCatching { builder.setIsStrongBoxBacked(true) }
            kpg.initialize(builder.build())
            kpg.generateKeyPair()
            null
        } catch (e: Exception) { e }
    }
}
