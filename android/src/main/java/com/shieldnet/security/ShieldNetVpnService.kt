package com.shieldnet.security

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * Android VpnService implementation of NetGuard + ShieldNet.
 * Intercepts outbound device traffic on tun0, parses TLS ClientHello SNI hostnames,
 * and blocks malicious domains before forwarding a single byte.
 */
class ShieldNetVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var job: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var shieldNet: ShieldNet
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null

    companion object {
        const val TAG = "ShieldNetVPN"
    }

    override fun onCreate() {
        super.onCreate()
        shieldNet = ShieldNet(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (vpnInterface == null) {
            startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        val builder = Builder()
            .setSession("ShieldNet Security")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setMtu(1500)

        vpnInterface = builder.establish()

        job = scope.launch {
            val fd = vpnInterface?.fileDescriptor ?: return@launch
            val inStream = FileInputStream(fd)
            val outStream = FileOutputStream(fd)
            inputStream = inStream
            outputStream = outStream
            val packet = ByteBuffer.allocate(32767)

            Log.i(TAG, "ShieldNet VPN Service started on tun0")

            while (isActive) {
                packet.clear()
                val length = try {
                    inStream.read(packet.array())
                } catch (e: Exception) {
                    break
                }

                if (length <= 0) {
                    // Interface closed or EOF
                    break
                }

                packet.limit(length)
                val sni = extractSniFromPacket(packet)

                if (sni != null) {
                    // Scan SNI domain with Tier 0 instant model
                    val scanResult = shieldNet.scan("https://$sni", depth = "tier0")
                    if (scanResult.decision == "block") {
                        Log.w(TAG, "BLOCKED malicious outbound connection to: $sni (${scanResult.category})")
                        // Packet is dropped (not forwarded to outStream)
                        continue
                    }
                }

                // In full gateway relay, forward allowed packets
            }
        }
    }

    /**
     * Inspects raw IP packet for TCP Port 443 TLS ClientHello SNI.
     */
    private fun extractSniFromPacket(packet: ByteBuffer): String? {
        try {
            val buffer = packet.array()
            val limit = packet.limit()
            if (limit < 40) return null

            val ipVersion = (buffer[0].toInt() shr 4) and 0x0F
            if (ipVersion != 4) return null

            val ipHeaderLen = (buffer[0].toInt() and 0x0F) * 4
            if (limit < ipHeaderLen + 20) return null

            val protocol = buffer[9].toInt()
            if (protocol != 6) return null // TCP only

            val tcpHeaderLen = ((buffer[ipHeaderLen + 12].toInt() shr 4) and 0x0F) * 4
            val payloadOffset = ipHeaderLen + tcpHeaderLen
            if (payloadOffset + 5 >= limit) return null

            // Check TLS Record ContentType = 22 (Handshake) and Version = TLS 1.0..1.3 (0x0301..0x0303)
            val contentType = buffer[payloadOffset].toInt()
            val major = buffer[payloadOffset + 1].toInt()
            if (contentType != 22 || major != 3) return null

            // Handshake Type 1 = ClientHello
            val handshakeType = buffer[payloadOffset + 5].toInt()
            if (handshakeType != 1) return null

            // Parse SNI extension (extension type 0x0000)
            var offset = payloadOffset + 43
            if (offset >= limit) return null
            val sessionLen = buffer[offset].toInt() and 0xFF
            offset += 1 + sessionLen

            if (offset + 2 >= limit) return null
            val cipherLen = ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
            offset += 2 + cipherLen

            if (offset + 1 >= limit) return null
            val compLen = buffer[offset].toInt() and 0xFF
            offset += 1 + compLen

            if (offset + 2 >= limit) return null
            val extTotalLen = ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
            offset += 2

            val end = (offset + extTotalLen).coerceAtMost(limit)
            while (offset + 4 <= end) {
                val extType = ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
                val extLen = ((buffer[offset + 2].toInt() and 0xFF) shl 8) or (buffer[offset + 3].toInt() and 0xFF)
                offset += 4

                if (extType == 0 && offset + extLen <= end) { // Server Name Indication
                    if (extLen >= 5) {
                        var sniOffset = offset + 2
                        val nameType = buffer[sniOffset].toInt()
                        if (nameType == 0) { // host_name
                            val nameLen = ((buffer[sniOffset + 1].toInt() and 0xFF) shl 8) or (buffer[sniOffset + 2].toInt() and 0xFF)
                            sniOffset += 3
                            if (sniOffset + nameLen <= limit) {
                                return String(buffer, sniOffset, nameLen, Charsets.US_ASCII)
                            }
                        }
                    }
                }
                offset += extLen
            }
        } catch (e: Exception) {
            return null
        }
        return null
    }

    override fun onDestroy() {
        job?.cancel()
        try {
            inputStream?.close()
        } catch (e: Exception) {
            // Ignore
        }
        try {
            outputStream?.close()
        } catch (e: Exception) {
            // Ignore
        }
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            // Ignore
        }
        vpnInterface = null
        try {
            shieldNet.close()
        } catch (e: Exception) {
            // Ignore
        }
        super.onDestroy()
    }
}
