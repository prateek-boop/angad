package com.shieldnet.security

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.nio.LongBuffer
import kotlin.math.exp
import kotlin.math.max

data class ThreatPrediction(
    val category: String,
    val confidence: Float,
    val riskScore: Float,
    val probabilities: Map<String, Float>
)

/**
 * On-device Tier 0 Threat Engine using ONNX Runtime Android.
 * Runs in ~15-25 ms on mobile ARM CPUs with subword WordPiece tokenization.
 */
class ShieldNetEngine(private val context: Context) {

    private val env: OrtEnvironment = OrtEnvironment.getEnvironment()
    private val session: OrtSession
    private val extractor = FeatureExtractor()
    private val tokenizer = WordPieceTokenizer(context)

    init {
        val modelFile = getModelFile("model_quantized.onnx")
        val options = OrtSession.SessionOptions().apply {
            setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT)
            setIntraOpNumThreads(2)
        }
        session = env.createSession(modelFile.absolutePath, options)
    }

    private fun getModelFile(filename: String): File {
        val file = File(context.filesDir, filename)
        if (!file.exists()) {
            context.assets.open(filename).use { input ->
                FileOutputStream(file).use { output ->
                    input.copyTo(output)
                }
            }
        }
        return file
    }

    /**
     * Run Tier 0 URL threat classification.
     */
    fun predict(url: String): ThreatPrediction {
        val features = extractor.extract(url)

        // Tokenize using exact WordPiece vocabulary
        val tokenized = tokenizer.encode(url, maxLength = 128)

        val shape = longArrayOf(1, 128)
        val inputIdsTensor = OnnxTensor.createTensor(env, LongBuffer.wrap(tokenized.inputIds), shape)
        val attentionMaskTensor = OnnxTensor.createTensor(env, LongBuffer.wrap(tokenized.attentionMask), shape)
        val tokenTypeIdsTensor = OnnxTensor.createTensor(env, LongBuffer.wrap(tokenized.tokenTypeIds), shape)

        val inputs = mapOf(
            "input_ids" to inputIdsTensor,
            "attention_mask" to attentionMaskTensor,
            "token_type_ids" to tokenTypeIdsTensor
        )

        val results = session.run(inputs)
        val logits = (results[0].value as Array<FloatArray>)[0]

        // Softmax
        var maxL = logits[0]
        for (l in logits) if (l > maxL) maxL = l
        val exp0 = exp(logits[0] - maxL)
        val exp1 = exp(logits[1] - maxL)
        val sumExp = exp0 + exp1
        var pSafe = exp0 / sumExp
        var pThreatBase = exp1 / sumExp

        // Apply 41-feature heuristic boosters
        val atTrick = features[6] > 0
        val isIp = features[14] > 0
        val suspTld = features[16] > 0
        val noHttps = features[20] == 0f
        val isExe = features[25] > 0
        val brandImp = features[32] > 0
        val brandSub = features[38] > 0

        var deceptiveScore = 0f
        if (brandSub) deceptiveScore += 0.4f
        if (brandImp) deceptiveScore += 0.3f
        if (atTrick) deceptiveScore += 0.4f
        if (suspTld && noHttps) deceptiveScore += 0.3f
        if (isIp && (isExe || noHttps)) deceptiveScore += 0.5f
        if (isExe) deceptiveScore += 0.4f

        val pThreat = if (deceptiveScore > 0f) {
            val boost = deceptiveScore.coerceAtMost(0.95f)
            pSafe = pSafe.coerceAtMost(1f - boost)
            max(pThreatBase, boost)
        } else {
            pThreatBase
        }

        var malware = 0f
        var scam = 0f
        var phishing = 0f

        val uLower = url.lowercase()
        if (isExe || (isIp && !isExe)) {
            malware = pThreat * 0.90f
            phishing = pThreat * 0.10f
        } else if (uLower.contains("iphone") || uLower.contains("claim") || uLower.contains("reward") || uLower.contains("free") || uLower.contains("crypto")) {
            scam = pThreat * 0.90f
            phishing = pThreat * 0.10f
        } else {
            phishing = pThreat * 0.95f
            scam = pThreat * 0.05f
        }

        val total = (pSafe + phishing + malware + scam).coerceAtLeast(0.0001f)
        val probs = mapOf(
            "safe" to (pSafe / total),
            "phishing" to (phishing / total),
            "malware" to (malware / total),
            "data_leak" to 0f,
            "scam" to (scam / total)
        )

        val bestCat = probs.maxByOrNull { it.value }?.key ?: "safe"
        val conf = probs[bestCat] ?: 0.5f
        val risk = 1f - (probs["safe"] ?: 0.5f)

        inputIdsTensor.close()
        attentionMaskTensor.close()
        tokenTypeIdsTensor.close()
        results.close()

        return ThreatPrediction(
            category = bestCat,
            confidence = conf,
            riskScore = risk,
            probabilities = probs
        )
    }

    fun close() {
        try {
            session.close()
        } catch (e: Exception) {
            // Ignore if already closed
        }
        try {
            env.close()
        } catch (e: Exception) {
            // Ignore if already closed
        }
    }
}
