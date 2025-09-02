package com.yu13140.verifiedboothash

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.File
import java.io.FileWriter
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate

class GetHashService : Service() {

    companion object {
        private const val TAG = "GetHashService"
        private const val CHANNEL_ID = "GetHashServiceChannel"
        private const val OUTPUT_FILENAME = "verified_boot_hash.txt"
        private const val KEYSTORE_ALIAS = "vbmeta-attestation-key"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Get VBHash Service")
            .setContentText("正在获取 Verified Boot Hash...")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .build()

        startForeground(1, notification)

        Thread {
            val hash = getVerifiedBootHash()
            val contentToWrite = if (!hash.isNullOrEmpty()) {
                hash
            } else {
                "Failed to get Verified Boot Hash."
            }

            Log.d(TAG, contentToWrite)
            writeToFile(contentToWrite)
            stopSelf()
        }.start()

        return START_NOT_STICKY
    }

    private fun getVerifiedBootHash(): String? {
        return try {
            generateAttestationKey()

            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val certificates = keyStore.getCertificateChain(KEYSTORE_ALIAS)
            keyStore.deleteEntry(KEYSTORE_ALIAS)

            if (certificates.isNullOrEmpty()) {
                Log.e(TAG, "Certificate chain is null or empty.")
                return null
            }

            val verifiedBootHashBytes = AttestationParser.parseVerifiedBootHash(certificates[0] as X509Certificate)
            verifiedBootHashBytes?.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            Log.e(TAG, "An exception occurred while getting verified boot hash", e)
            null
        }
    }

    private fun generateAttestationKey() {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).setAttestationChallenge("get-vb-hash".toByteArray())
         .setDigests(KeyProperties.DIGEST_SHA256)
         .build()
        kpg.initialize(parameterSpec)
        kpg.generateKeyPair()
    }

    private fun writeToFile(data: String) {
        val file = File(filesDir, OUTPUT_FILENAME)
        try {
            FileWriter(file).use { it.write(data) }
            Log.d(TAG, "Successfully wrote to file: ${file.absolutePath}")
        } catch (e: IOException) {
            Log.e(TAG, "Failed to write to file", e)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                "Get Hash Service Channel",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(serviceChannel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null
}