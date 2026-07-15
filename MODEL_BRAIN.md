# ShieldNet Repository Brain

This is the core logic of the repository. Use this file as the reference when building a stronger replacement model.

## 1. Core Problem

The repository builds a URL threat classifier.

Input:

```text
raw URL string
```

Output:

```text
one of: safe, phishing, malware, data_leak, scam
```

The model is not a browser, crawler, or live website analyzer. Its current brain works mostly from the URL text itself.

## 2. Current Model Contract

Any stronger model should keep this contract unless the API is also changed.

### Inputs

The current model takes two inputs:

```text
url_input:     shape (batch, 200), dtype int32
feature_input: shape (batch, 41),  dtype float32
```

### Output

The model returns five softmax probabilities:

```text
[safe, phishing, malware, data_leak, scam]
```

Example:

```json
{
  "safe": 0.02,
  "phishing": 0.94,
  "malware": 0.02,
  "data_leak": 0.01,
  "scam": 0.01
}
```

The predicted class is the highest probability.

## 3. Label Brain

File:

```text
config.py
```

Current class order:

```python
THREAT_CLASSES = ["safe", "phishing", "malware", "data_leak", "scam"]
```

Do not change this order unless you also update:

- `api/models/schemas.py`
- `ml_engine/explainer.py`
- `ml_engine/model.py`
- `ml_engine/quantized_detector.py`
- saved model consumers

The class index is part of the system contract.

## 4. Preprocessing Brain

The model does not receive the raw URL directly. The raw URL is converted into two representations.

### A. Character Tokens

File:

```text
ml_engine/url_tokenizer.py
```

Purpose:

```text
convert URL characters into integer IDs
```

Rules:

- Max URL length is 200.
- Short URLs are padded with `0`.
- Long URLs are truncated.
- Unknown characters become `1`.
- Characters include letters, digits, and common URL symbols.

This creates:

```text
url_input: int32 vector of length 200
```

This branch lets the model learn patterns such as:

- `paypa1`
- `secure-login`
- `verify-account`
- `.xyz`
- random-looking strings
- suspicious path/file names

### B. Engineered Features

File:

```text
ml_engine/feature_extractor.py
```

Purpose:

```text
convert the URL into 41 numeric security features
```

This creates:

```text
feature_input: float32 vector of length 41
```

The 41 features are the hand-built knowledge in this repository.

## 5. The 41 Feature Brain

The current model depends heavily on these features.

| Index | Feature |
|---:|---|
| 0 | `url_length` |
| 1 | `num_dots` |
| 2 | `num_hyphens` |
| 3 | `num_underscores` |
| 4 | `num_digits` |
| 5 | `num_special_chars` |
| 6 | `has_at_symbol` |
| 7 | `path_depth` |
| 8 | `num_query_params` |
| 9 | `has_fragment` |
| 10 | `url_entropy` |
| 11 | `consecutive_consonants` |
| 12 | `domain_length` |
| 13 | `subdomain_depth` |
| 14 | `is_ip_address` |
| 15 | `uses_url_shortener` |
| 16 | `suspicious_tld` |
| 17 | `has_punycode` |
| 18 | `domain_digit_ratio` |
| 19 | `tld_length` |
| 20 | `is_https` |
| 21 | `has_port` |
| 22 | `port_is_standard` |
| 23 | `double_slash_in_path` |
| 24 | `hex_encoded_chars` |
| 25 | `suspicious_file_extension` |
| 26 | `has_login_keyword` |
| 27 | `has_secure_keyword` |
| 28 | `has_account_keyword` |
| 29 | `has_update_keyword` |
| 30 | `has_verify_keyword` |
| 31 | `has_bank_keyword` |
| 32 | `brand_impersonation_score` |
| 33 | `url_shortening_chain` |
| 34 | `excessive_subdomains` |
| 35 | `random_looking_domain` |
| 36 | `long_subdomain` |
| 37 | `path_length_ratio` |
| 38 | `known_brand_in_subdomain` |
| 39 | `misleading_tld` |
| 40 | `homoglyph_score` |

If you build a stronger model, either:

1. Keep these 41 features exactly, so the current API and runtime remain compatible.
2. Add new features and update `MODEL_CONFIG["num_features"]`, the model input shape, training data generation, inference wrappers, and TFLite consumers.

## 6. Current Neural Brain

File:

```text
ml_engine/model.py
```

Class:

```text
ThreatDetectionModel
```

Model name:

```text
ShieldNet_v2_Attention
```

The current model is a dual-branch TensorFlow/Keras network.

```text
                    raw URL
                       |
        ---------------------------------
        |                               |
        v                               v
  character tokens                41 features
        |                               |
        v                               v
  CNN + Attention branch          Dense feature branch
        |                               |
        ----------- concatenate --------
                       |
                       v
               dense fusion head
                       |
                       v
              5-class softmax output
```

### Branch 1: URL Character CNN

This branch learns directly from URL characters.

Flow:

```text
url_input
-> Embedding
-> Conv1D kernel 2
-> Conv1D kernel 3
-> Conv1D kernel 5
-> Conv1D kernel 7
-> concatenate
-> Conv1D
-> attention
-> global max pooling
-> global average pooling
-> dense layers
```

Role:

```text
learn suspicious character patterns and URL substrings
```

### Branch 2: Feature DNN

This branch learns from the 41 handcrafted risk features.

Flow:

```text
feature_input
-> batch normalization
-> dense block
-> dense block with residual add
-> dense block
```

Role:

```text
learn risk combinations from explicit URL security features
```

Example combinations:

```text
suspicious_tld + has_login_keyword + brand_impersonation_score
is_ip_address + suspicious_file_extension
no_https + verify_keyword + misleading_tld
```

### Fusion Head

The fusion head combines both branches.

Flow:

```text
CNN output + feature DNN output
-> concatenate
-> dense 256
-> dense 128
-> dense 64
-> dense 5 with softmax
```

Role:

```text
combine learned URL text patterns with engineered risk signals
```

## 7. Training Brain

File:

```text
ml_engine/train_model.py
```

Training pipeline:

```text
load or generate URLs
-> tokenize URLs
-> extract 41 features
-> create labels
-> stratified train/validation/test split
-> train TensorFlow model
-> evaluate
-> save Keras model and metrics
```

Supported dataset modes:

```text
synthetic
real
combined
```

Command:

```bash
python main.py train --dataset combined --samples 50000 --epochs 30
```

Important training settings:

```text
optimizer: Adam
loss: sparse_categorical_crossentropy
metric: accuracy
batch size: 64
learning rate: 0.001 with cosine decay
early stopping: validation loss
best checkpoint: validation accuracy
```

Saved model:

```text
ml_engine/saved_model/shieldnet_model.keras
```

Best checkpoint:

```text
ml_engine/saved_model/best_model.keras
```

## 8. Data Brain

The repository has two data sources.

### Synthetic Data

File:

```text
ml_engine/dataset_generator.py
```

This generates fake but realistic-looking URLs for:

- safe
- phishing
- malware
- data_leak
- scam

This is useful for bootstrapping, but a stronger model should not rely only on synthetic data.

### Real Data

File:

```text
ml_engine/real_data_loader.py
```

Real data can come from:

- URLhaus
- OpenPhish
- PhishTank
- Tranco or Majestic safe-domain lists
- local Kaggle CSV datasets

A stronger model should use more real, fresh, carefully labeled URLs.

## 9. Inference Brain

The runtime path is:

```text
URL
-> URLTokenizer
-> FeatureExtractor
-> model.predict_with_confidence()
-> ThreatExplainer
-> API or CLI result
```

Files:

```text
main.py
api/server.py
api/routes/scan.py
ml_engine/explainer.py
```

The API returns:

```text
category
confidence
risk_score
threat_level
reasons
recommendation
blocked
probabilities
scan_time_ms
```

The blocking decision is simple:

```text
blocked = predicted class is not "safe"
```

## 10. Explainability Brain

File:

```text
ml_engine/explainer.py
```

The explainer does not explain the neural network internally. It explains the engineered features.

It checks feature thresholds and creates human-readable reasons such as:

- URL uses suspicious TLD.
- URL uses IP address instead of domain.
- URL uses shortener.
- URL lacks HTTPS.
- URL contains login or verify keywords.
- URL appears to impersonate a brand.
- URL has executable/archive extension.
- URL has homoglyph attack patterns.

This is important: the explainability is heuristic, not deep model attribution.

## 11. Quantized Brain

Files:

```text
ml_engine/quantize_model.py
ml_engine/quantized_detector.py
```

The trained Keras model can be converted to TFLite.

Current lightweight model:

```text
ml_engine/saved_model/shieldnet_quantized_dynamic.tflite
```

This is used for faster CPU inference and smaller deployment size.

If you build a stronger model, remember that some architectures may be harder to convert to TFLite.

## 12. Current Strengths

The current brain is good because:

- It combines raw URL learning and engineered features.
- It has a clear API contract.
- It can train from synthetic and real data.
- It has a TFLite path for lightweight deployment.
- It gives user-facing reasons through the explainer.
- It separates preprocessing, model, training, inference, and API code cleanly.

## 13. Current Weaknesses

These are the main reasons to build a stronger model.

### 1. It only looks at the URL

It does not inspect:

- live webpage HTML
- JavaScript
- forms
- redirects
- TLS certificate details
- WHOIS/domain age
- DNS records
- page screenshots
- downloaded file hashes
- reputation APIs

### 2. Synthetic data can make the model overconfident

Synthetic phishing and scam URLs may be too pattern-based. The model can learn generator artifacts instead of real attacker behavior.

### 3. The safe class is the hardest class

The saved metrics show lower accuracy for `safe` than for threat classes. This means false positives are likely the biggest practical risk.

### 4. Explanations are feature-threshold based

The explainer explains URL features, not the actual neural network decision.

### 5. Class labels are broad

`phishing`, `malware`, `data_leak`, and `scam` can overlap in real life.

### 6. No calibrated uncertainty

The softmax confidence is not true real-world probability.

## 14. What To Preserve In A Stronger Model

When replacing the model, preserve these unless you intentionally redesign the whole app:

```text
input URL -> prediction -> explanation -> blocked/allowed decision
```

Preserve:

- class order: `safe`, `phishing`, `malware`, `data_leak`, `scam`
- API response format
- preprocessing reproducibility
- saved model loading path or loader logic
- batch scan support
- TFLite/export plan if mobile or lightweight deployment matters
- explainable reasons for user trust

## 15. Best Upgrade Path

For a stronger model, the best direction is not only "bigger neural net". The biggest gain will come from better evidence.

Recommended stronger architecture:

```text
URL text encoder
  + engineered URL features
  + domain/reputation features
  + redirect/TLS/DNS/WHOIS features
  + optional webpage content features
  -> fusion model
  -> calibrated threat probabilities
  -> explanation layer
```

High-value new features:

- domain age
- registrar
- DNS record age
- nameserver reputation
- TLS issuer and certificate age
- redirect chain length
- final URL mismatch
- HTML form action domain mismatch
- password field presence
- hidden input count
- external script count
- iframe count
- page title/brand mismatch
- favicon/brand similarity
- screenshot similarity to known brands
- blacklist or reputation feed hits

Better model ideas:

- character transformer instead of CNN-only URL branch
- pretrained URL/text encoder
- gradient boosted tree over engineered features
- neural + tree ensemble
- calibrated classifier using temperature scaling or isotonic regression
- separate binary safety model plus multiclass threat-type model

## 16. Minimal Replacement Checklist

If you build a new model and want it to plug into this repo:

1. Keep or update `URLTokenizer`.
2. Keep or update `FeatureExtractor`.
3. Make sure model input shapes match inference code.
4. Keep output shape `(batch, 5)`.
5. Keep class order unchanged.
6. Update `ThreatDetectionModel.load()`.
7. Update `predict_with_confidence()` if the output format changes.
8. Update `ThreatExplainer` if features change.
9. Retrain and save `shieldnet_model.keras`.
10. Rebuild `shieldnet_quantized_dynamic.tflite` if TFLite is needed.
11. Test `python main.py test "<url>"`.
12. Test `POST /api/v1/scan`.

## 17. One-Line Brain Summary

```text
ShieldNet converts a URL into character tokens and 41 risk features, sends both through a dual-branch TensorFlow model, predicts one of five threat classes, then uses feature-based explanations to decide whether to block or allow the URL.
```
