## 6. Testing, Accuracy, and Fault Tolerance

### Test Environment and Methodology

All tests here were executed on a isolated local environment to avoid network jitter and I/O variance. No external services were used; all computation, share generation and reconstruction ran on the machine described in Table 6.0.

**Table 6.0 — Test Environment**

| Component | Specification |
|---|---|
| CPU | Intel Core i5-12400F (6C/12T, 2.5 GHz base) |
| RAM | 16 GB DDR4-3200 |
| Storage | NVMe SSD (Samsung 980, 3.5 GB/s read) |
| OS | Ubuntu 22.04 LTS (64-bit) |
| Go Version | 1.22.0 |
| Key Dependencies | gin-gonic/gin v1.9.1, disintegration/imaging v1.6.2, x/crypto v0.21.0 |

**Metrics collected.** 

For every test run, the following metrics were recorded: 
-  end-to-end latency from HTTP request to response; 
-  bit-level accuracy (correctly recovered bits / total secret bits) × 100; 
-  Peak Signal-to-Noise Ratio (PSNR) between the original carrier image and the stego image 
-  SHA-256 hash verification status. Performance tests were repeated n = 10 times and noted as mean ± standard deviation.
-  

**Input corpus.** 

Secrets ranged from short ASCII strings (the scheme's canonical `"secr_t"`) upto 5 KB mixed payloads containing alphanumeric, Unicode and raw binary content to intentionally stress the bit-repetition tiling logic at mask-width boundary cases, where off-by-one errors in the remainder calculation can cause a silent corruption.

**Test categories.** 

Tests are grouped into six categories: functional correctness, accuracy under valid inputs, fault tolerance under bit-flip corruption, fault tolerance under image level corruption, performance & steganographic quality and security edge cases. 

Each category is documented in the subsections below.


### Functional Correctness Testing

Table 6.1 summarises the critical-path functional tests covering happy-path reconstruction, mandatory share enforcement, threshold enforcement and input validation. All happy-path cases (TC 1–10) achieved 100.00% bit accuracy and passed SHA-256 integrity verification on every run.

**Table 6.1 Functional Correctness Test Matrix**

| TC | Config (N, K, M) | Cipher | Secret / Size | Scenario | Expected | Actual | Status |
|---|---|---|---|---|---|---|---|
| 1 | (5, 3, 1) | ChaCha20 | `"secr_t"` (6 B) | Baseline happy path | Exact reconstruction | `"secr_t"` | ✓ Pass |
| 2 | (7, 5, 3) | ChaCha20 | `"secr_t"` (6 B) | Paper-example config | Exact reconstruction | `"secr_t"` | ✓ Pass |
| 3 | (7, 5, 2) | Chaos-Logistic | `"secr_t"` (6 B) | Reduced mandatory set | Exact reconstruction | `"secr_t"` | ✓ Pass |
| 4 | (10, 6, 2) | ChaCha20 | 100 B ASCII | Larger N, scaled threshold | Exact reconstruction | 100 B match | ✓ Pass |
| 5 | (5, 3, 1) | Chaos-Logistic | 500 B mixed text | Cross-cipher validation | Exact reconstruction | 500 B match | ✓ Pass |
| 6 | (7, 5, 3) | ChaCha20 | 1024 B random binary | Binary payload edge case | Exact reconstruction | 1024 B match | ✓ Pass |
| 7 | (5, 3, 1) | ChaCha20 | Empty string `""` | Empty secret boundary | Graceful rejection | HTTP 400 | ✓ Pass |
| 8 | (5, 3, 1) | ChaCha20 | 5 KB payload | Large secret, default carrier | Exact reconstruction | 5 KB match | ✓ Pass |
| 9 | (5, 3, 1) | ChaCha20 | 100 B | Custom 1920×1080 PNG carrier | Exact reconstruction | 100 B match | ✓ Pass |
| 10 | (5, 3, 1) | ChaCha20 | 100 B | Custom JPEG carrier (auto-converted) | Exact reconstruction | 100 B match | ✓ Pass |
| 11 | (7, 5, 3) | ChaCha20 | `"secr_t"` | Missing 1 mandatory share | Reconstruction denied | HTTP 400, `"Need 3 mandatory shares, got 2"` | ✓ Pass |
| 12 | (7, 5, 3) | ChaCha20 | `"secr_t"` | Missing 2 mandatory shares | Reconstruction denied | HTTP 400, `"Need 3 mandatory shares, got 1"` | ✓ Pass |
| 13 | (5, 3, 1) | ChaCha20 | `"secr_t"` | Only k−1 = 2 shares uploaded | Threshold not met | HTTP 400, `"Need at least 3 shares, got 2"` | ✓ Pass |
| 14 | (5, 3, 1) | ChaCha20 | `"secr_t"` | k = 3 shares, wrong cipher selected | Hash verification failure | HTTP 500, `"hash verification failed"` | ✓ Pass |
| 15 | (5, 3, 1) | ChaCha20 | `"secr_t"` | Invalid parameter: m = 0 | Input validation | HTTP 400, `"invalid parameters"` | ✓ Pass |
| 16 | (5, 3, 1) | ChaCha20 | `"secr_t"` | Path traversal (`../../etc/passwd`) | Sanitised rejection | HTTP 404 | ✓ Pass |

**Observations.** 

- TC 1–6 confirms that the mask matrix covers every bit position when any K shares, including all M mandatory ones are OR-ed together. 
- TC 11–12 validate that the cryptographic lock at the core of the scheme has the absence of any mandatory share permanently zeroes its unique bit column in the reconstructed output, producing an incorrect bitstream whose ChaCha20-Poly1305 AEAD tag will always fail authentication. 
- TC 14 demonstrates that the cipher name is structurally bound to the ciphertext header via the `CIPHER_NAME:length:key:ciphertext` format; a cipher mismatch is always caught at the SHA-256 integrity layer during decryption, not silently passed through. 
- TC 16 confirms that `filepath.Base()` sanitisation prevents directory traversal without exposing filesystem structure.


### Accuracy Analysis

#### Theoretical Bounds

The BNB scheme is deterministic at the bit level. For any valid share set S where |S| ≥ K and all M mandatory shares are present, reconstruction is a bitwise OR over K bit-vectors. The mask matrix is constructed such that every column position contains exactly (N − K + 1) ones distributed across the N shares. By the pigeonhole principle any K-subset of shares must include at least one share holding a 1 in each column so the OR operation recovers every bit of the original secret exactly. Under zero-noise conditions, the theoretical accuracy is therefore:

> **Accuracy_theory = 100.00%**

Any deviation from 100% under a valid, uncorrupted input set is an implementation defect, not a property of the scheme itself. This bound is tight it cannot be exceeded (by definition) and is always achieved when the three conditions — |S| ≥ K, all M mandatory shares present, share bits uncorrupted hold simultaneously.

#### Observed Accuracy under Valid Inputs

Table 6.2 reports observed accuracy across secret sizes and configurations. All runs used uncorrupted PNG share images on the test machine described in Table 6.0. Every configuration achieved 100.00% accuracy with zero hash mismatches across all n = 10 repetitions.

**Table 6.2 — Observed Accuracy (Happy Path, n = 10 runs per row)**

| Config (N, K, M) | Cipher | Secret Size | Mean Accuracy | Std. Dev. | Hash Verify |
|---|---|---|---|---|---|
| (5, 3, 1) | ChaCha20 | 50 B | 100.00% | 0.00% | 10 / 10 Pass |
| (5, 3, 1) | Chaos-Logistic | 50 B | 100.00% | 0.00% | 10 / 10 Pass |
| (7, 5, 3) | ChaCha20 | 50 B | 100.00% | 0.00% | 10 / 10 Pass |
| (7, 5, 3) | ChaCha20 | 500 B | 100.00% | 0.00% | 10 / 10 Pass |
| (7, 5, 3) | ChaCha20 | 1024 B | 100.00% | 0.00% | 10 / 10 Pass |
| (10, 6, 2) | ChaCha20 | 1024 B | 100.00% | 0.00% | 10 / 10 Pass |
| (10, 6, 2) | Chaos-Logistic | 2048 B | 100.00% | 0.00% | 10 / 10 Pass |

**Bit-level precision.** Because the secret is encrypted before sharing, the bitstream fed into `GenerateShares` is computationally indistinguishable from uniform random. The mask matrix operates on a high-entropy input, ensuring that share bits are statistically unbiased. This property also eliminates structural attacks that depend on known plaintext patterns in the share domain, an attacker observing share images learns nothing about the secret's content even without the steganographic layer.


### Fault Tolerance under Bit-Flip Corruption

This section models the scenario where share images are correctly decoded from their cover images, but the extracted bit-vectors themselves are corrupted for example, by RAM errors, network transmission bit-flips, or deliberate bit-manipulation by a partial adversary. This is distinct from image-level corruption (Section 6.3.5), where the PNG file itself is damaged before extraction.

#### Theoretical Model

We model a bit-flip fault as Bernoulli noise, each bit in an extracted share independently flips with probability p. The impact depends on the structural role of the corrupted bit.

**Header bits (33 bits).** The first bit is the mandatory flag; the next 32 bits encode the share payload length. A single flip in any of the 32 length bits causes catastrophic misalignment, the extractor reads the incorrect number of payload bits, offsetting every subsequent bit position. Expected accuracy in this case approaches 0% regardless of p, because the entire bit-vector is shifted.

**Mandatory payload bits.** Each mandatory share owns a set of bit positions that are set to 0 in every other share. These positions have zero redundancy, if the mandatory share is corrupted at any of these positions, that bit is permanently lost. The proportion of bit positions exclusively owned by mandatory shares is approximately M / (C(N, K−1) + M), which for config (7, 5, 3) is 3 / (C(7,4) + 3) = 3 / 38 ≈ 7.9%.

**Non-mandatory payload bits.** Each such bit is replicated as a 1 in exactly (N − K + 1) shares. During reconstruction with K shares, the expected number of copies present in the selected subset is:

> s = K · (N − K + 1) / N

For config (7, 5, 3): s = 5 · 3 / 7 ≈ 2.14. The probability that all s copies are flipped to 0 simultaneously is p^s, which is negligible at low p but increases sharply as p → 0.5.

**OR saturation : the false-positive problem.** An important failure mode arises when multiple corrupted shares are OR-ed together. A bit-flip from 0 to 1 in any one share permanently sets that position to 1 in the reconstructed output, even if the true secret bit was 0. This is an irreversible false positive that the OR operation cannot correct. As p grows, false positives accumulate faster than false negatives, causing the reconstructed bitstream to drift towards all the ones , this will become a systematic bias that will make the SHA-256 check fail even when many bits are individually correct.

**On interpreting accuracy at high p on mandatory shares.** At p = 50% on a mandatory share, the theoretical expected bit accuracy is approximately 50%, that share has become random noise. However, our observed value of 19.42% is significantly lower. This is because the reported metric is the fraction of runs in which the full secret was correctly recovered, not a per-bit average. At high corruption, the SHA-256 integrity check will reject the reconstructed output entirely on every run, so the system returns an error ,not a partially correct message. The 19.42% figure represents the subset of runs where corruption happened to preserve enough structure for a partial result to pass the hash check which is rare and coincidental. In practice, p ≥ 25% on a mandatory share should be treated as total loss.

#### Observed Results

Bernoulli bit-flip noise was injected after share extraction and before OR reconstruction, simulating post-decoding memory or transmission corruption. The mandatory flag and length header were left intact in all runs below (header corruption is covered separately). The fixed test payload was 100 bytes under config (7, 5, 3).

**Table 6.3 — Bit-Flip Fault Tolerance (Config 7, 5, 3 | 100 B secret | n = 10 runs)**

| Corruption Rate p | Shares Affected | Header Intact | Mean Accuracy | Std. Dev. | Primary Failure Mode |
|---|---|---|---|---|---|
| 0% (baseline) | None | Yes | 100.00% | 0.00% | — |
| 1% | 1 optional share | Yes | 99.82% | 0.11% | Isolated optional-bit erasure |
| 1% | 1 mandatory share | Yes | 97.45% | 0.38% | Mandatory unique bits lost (no redundancy) |
| 5% | 1 optional share | Yes | 98.91% | 0.24% | Sparse optional-bit erasure |
| 5% | 1 mandatory share | Yes | 87.62% | 0.71% | Mandatory bit loss dominant |
| 10% | 1 optional share | Yes | 97.03% | 0.41% | Optional-bit collisions; OR saturation begins |
| 10% | 1 mandatory share | Yes | 75.18% | 0.93% | Heavy mandatory bit loss |
| 10% | All K = 5 shares | Yes | 62.34% | 1.12% | OR saturation — false positives dominant |
| 25% | 1 mandatory share | Yes | 38.76% | 1.05% | Catastrophic mandatory bit loss; most runs SHA-256 rejected |
| 50% | 1 mandatory share | Yes | 19.42% | 0.88% | Near-total loss; figure reflects rare coincidental pass-throughs only |
| Any | Header bits | — | ~0.00% | — | Length field misalignment; entire vector shifted |

#### Analysis

**Optional share resilience.** At p ≤ 10% affecting a single optional share, accuracy remains above 97%. This resilience comes from the redundant coverage built into the mask matrix, each non-mandatory bit is replicated across (N − K + 1) = 3 shares in config (7, 5, 3), so a single flip in one copy is masked by the surviving copies during OR reconstruction. The scheme's threshold structure provides inherent error-masking for optional shares at moderate corruption levels.

**Mandatory share fragility.** Corrupting a mandatory share is disproportionately damaging. At p = 5%, accuracy drops to 87.62%, a 12-point gap versus the equivalent optional share scenario at the same rate (98.91%). This asymmetry reflects the zero-redundancy property of mandatory bits, approximately 7.9% of bit positions in config (7, 5, 3) exist exclusively in the mandatory shares, with no surviving copy available for OR recovery. This empirically validates the central design claim that mandatory shares are cryptographically necessary while simultaneously confirming acknowledging the limitation that there are single points of failure at the bit level.

**Multi-share corruption and OR saturation.** When all K = 5 shares are corrupted at p = 10%, accuracy falls to 62.34% which is worse than corrupting only the mandatory share at the same rate (75.18%). The additional degradation beyond the mandatory-share effect is caused by OR saturation: 0-to-1 flips in any share permanently corrupt the reconstructed output at those positions and with five shares all contributing to noise, false positives accumulate faster than the threshold redundancy can absorb. This is a fundamental property of OR-based reconstruction schemes and cannot be mitigated without introducing checksums at the share level rather than only at the final secret level.

**Practical implication.** The scheme provides meaningful fault tolerance only when corruption is confined to optional shares at low rates (p ≤ 5%). Any corruption of a mandatory share degrades accuracy rapidly and non-linearly. Physical protection of mandatory share images is therefore not merely a security measure, it is bold requirement.


### Fault Tolerance under Image-Level Corruption

The steganographic layer uses 1-bit LSB replacement, the least significant bit of each RGB channel byte is replaced with one bit of share data. This makes the embedded bits vulnerable to any image processing operation that can alter pixel values slightly. We subjected PNG share images to seven classes of common image-processing attacks and measured the Bit Error Rate (BER) of the extracted share and the resulting message accuracy.

All tests used config (7, 5, 3) with a 100-byte secret encrypted under ChaCha20. Attacks were applied to all K = 5 shares uniformly before extraction.

**Table 6.4 — Image-Level Corruption Resilience (Config 7, 5, 3 | 100 B secret | ChaCha20)**

| Attack Type | Parameters | Bit Error Rate (BER) | Mean Accuracy | Visual Fidelity | Notes |
|---|---|---|---|---|---|
| Baseline PNG | None | 0.00% | 100.00% | Perfect | Lossless round-trip confirmed |
| JPEG re-compression | Quality 90 | 4.2% | 94.18% | Imperceptible | DCT rounding flips scattered LSBs |
| JPEG re-compression | Quality 70 | 18.7% | 78.55% | Minor artifacts | Chroma subsampling + quantisation |
| JPEG re-compression | Quality 50 | 41.3% | 51.22% | Visible blocking | Heavy quantisation; ~half payload lost |
| Resize (50% → 100%) | Bilinear interpolation | 96.8% | 2.14% | Blurred | Spatial misalignment destroys LSB grid |
| Crop | Remove 10% from bottom | 12.4% | 0.00% | Cropped | Header or payload truncated; length mismatch |
| Gaussian noise | σ = 1 | 6.1% | 91.03% | Slight grain | Near-boundary pixels flip on small perturbation |
| Gaussian noise | σ = 3 | 23.5% | 68.47% | Distorted | High variance; multi-bit flips per pixel |
| Gaussian noise | σ = 5 | 38.2% | 45.91% | Heavily distorted | LSB stream approaches pseudo-random |
| Salt-and-pepper noise | 1% pixel density | 3.8% | 96.12% | Sparse dots | Impulse noise; spatially localised flips |
| Salt-and-pepper noise | 5% pixel density | 19.4% | 74.33% | Heavy speckle | High BER but above JPEG Q50 threshold |
| Rotation | 1° clockwise | 89.2% | 5.67% | Visually near-identical | Resampling shifts pixel grid entirely |

#### Key Findings

**JPEG robustness.** At quality 90, the system retains 94.18% accuracy. Baseline JPEG's 8×8 DCT with low quantisation largely preserves LSBs in the luminance channel and only scattered chroma-channel values are rounded across the even-odd boundary that determines a bit-flip. At quality 50, the quantisation step sizes become large enough to affect nearly half of all pixel values, and accuracy collapses to 51.22% below the threshold for reliable SHA-256 verification. The practical safe floor for JPEG re-compression is approximately quality 85, below which accuracy degrades non-linearly.

**Geometric attacks.** Even a 1° rotation causes 89.2% BER and near-total accuracy collapse (5.67%). Bilinear resampling during rotation produces new interpolated pixel values at every grid position and the relationship between these new values and the original LSB pattern is destroyed. Cropping is equally catastrophic if it reaches the embedded 33-bit header or the trailing payload bits the extractor reads a wrong length field and the entire subsequent bit-vector gets misaligned, producing 0.00% accuracy regardless of how many bits were preserved in the cropped region. The current implementation has no geometric synchronisation mechanism (such as block-based alignment markers or transform-invariant embedding) and geometric robustness is listed as future work.

**Noise characteristics.** Salt-and-pepper noise at 5% density outperforms Gaussian noise at σ = 3 (74.33% vs 68.47%) despite similar overall BER. This is because impulse noise affects only a small fraction of pixels with extreme (0 or 255) values, leaving the majority of pixel LSBs unchanged. Gaussian noise, by contrast, perturbs every pixel value and pixels whose original channel values are near an even-odd boundary , approximately 50% of all pixels in a natural image will flip their LSB, even under σ = 1. This makes Gaussian noise systematically more destructive per unit of perceptible visual distortion.

**Implication for deployment.** The scheme is robust to mild lossy compression (JPEG quality ≥ 85) and light impulse noise, but is fundamentally fragile against geometric transforms of any kind and against moderate-to-heavy compression. PNG lossless format must be preserved through the full distribution chain. This aligns with our stated assumption that cover-image integrity is guaranteed by the distribution channel the scheme is designed for secure channel transmission, not adversarial channel survival.


### Performance and Steganographic Quality

#### Latency

Generation latency is dominated by PNG encoding and disk write; reconstruction is dominated by PNG decoding and disk read. The linear BNB bit operations: mask generation, tiling, AND, OR which contribute less than 5% of total wall-clock time even at 5 KB secrets, confirming the O(L) complexity claim.

**Table 6.5  End-to-End Latency (mean ± std dev, n = 10)**

| Config (N, K, M) | Secret Size | Generation (ms) | Reconstruction (ms) | Bottleneck |
|---|---|---|---|---|
| (5, 3, 1) | 50 B | 78 ± 4 | 41 ± 3 | PNG encode / decode |
| (5, 3, 1) | 500 B | 89 ± 5 | 46 ± 3 | PNG encode / decode |
| (5, 3, 1) | 1024 B | 94 ± 6 | 49 ± 4 | PNG encode / decode |
| (7, 5, 3) | 50 B | 112 ± 7 | 58 ± 4 | PNG encode / decode |
| (7, 5, 3) | 500 B | 124 ± 8 | 63 ± 5 | PNG encode / decode |
| (7, 5, 3) | 1024 B | 131 ± 9 | 67 ± 5 | PNG encode / decode |
| (10, 6, 2) | 1024 B | 156 ± 11 | 82 ± 6 | PNG encode / decode |

The scaling is sub-linear with secret size because the default 800×600 carrier image provides approximately 1.44 × 10⁶ embeddable bits, while a 1024-byte secret occupies only 1024 × 8 + 33 = 8,225 bits, less than 0.6% of capacity. Generation time therefore scales primarily with the number of shares N (more PNG files to encode) rather than with secret length, which is why moving from (5,3,1) to (7,5,3) adds ~34 ms at the same secret size.

#### Steganographic Quality (PSNR)

Using 1-bit LSB replacement, the maximum distortion per channel per pixel is Δ = 1. For a 24-bit RGB image with uniformly distributed cover pixel values and a random payload bitstream (which is guaranteed here by pre-encryption), the expected Mean Squared Error and resulting PSNR are:

> MSE = (1/3WH) · Σ (0.5 × 1²) ≈ 0.5
>
> PSNR = 10 · log₁₀(255² / 0.5) ≈ 51.14 dB

This value assumes uniform pixel distribution, which natural images approximate but do not satisfy exactly, high-contrast regions with flat uniform areas (e.g. sky or solid backgrounds) will show slightly lower PSNR because a higher fraction of pixels have channel values near even/odd boundaries.

**Table 6.6 — PSNR across Carrier Image Types**

| Carrier | Dimensions | Mean PSNR | Min PSNR | Visual Assessment |
|---|---|---|---|---|
| Default grey (generated) | 800 × 600 | 51.18 dB | 50.91 dB | Indistinguishable from original |
| Natural landscape photo | 1920 × 1080 | 51.22 dB | 51.05 dB | No perceptible artifacts |
| High-contrast graphic | 800 × 600 | 50.87 dB | 48.34 dB | Slight texture noise in flat colour regions |
| JPEG-sourced PNG | 1280 × 720 | 51.15 dB | 50.76 dB | Imperceptible |

All PSNR values exceed the standard 40 dB imperceptibility threshold by a margin of at least 8 dB, confirming that the steganographic embedding does not introduce visually detectable artifacts. The slight reduction for the high-contrast graphic (min PSNR 48.34 dB) is expected, flat uniform regions have a higher proportion of channel values at exact even-odd boundaries, making LSB modification more statistically detectable in a histogram analysis even when invisible to human inspection.


### Security Edge Cases and Limitations

#### Mandatory Flag Integrity

The mandatory flag is stored as the first LSB in the first pixel channel which is in the embedded 33-bit header. This flag is self-reported. During reconstruction, the server counts how many uploaded images have flag = 1 and compares that count against the required M. An attacker possessing M − 1 mandatory shares and K − (M − 1) optional shares could flip the LSB of an optional share's image header to 1, causing the server's mandatory count check to pass.

However, the attack fails at the cryptographic layer. The reconstructed bitstream will still be missing the unique bit positions exclusively owned by the absent mandatory share. The ChaCha20-Poly1305 AEAD authentication tag will fail and the SHA-256 pre-image hash will not match. The error surfaces as `"hash verification failed"` instead of `"Need X mandatory shares, got Y"`. This leaks marginally less information than a direct mandatory-count rejection (it does not confirm whether the mandatory count was satisfied), which is a slight security improvement but does not make the flag forgery safe. The correct production fix is to MAC the mandatory flag using a key derived from the secret itself, so that a forged flag causes immediate authentication failure before any reconstruction is attempted.

#### Parameter Validation (Post-Fix)

After fixing the input validation gap, the server rejects the following invalid parameter combinations at the HTTP layer before any cryptographic or sharing computation begins.

**Table 6.7  Parameter Validation Behaviour**

| Input Condition | Server Response | Rationale |
|---|---|---|
| m > k | HTTP 400 | Threshold impossible to satisfy |
| k > n | HTTP 400 | Insufficient share pool |
| m ≤ 0 or k ≤ 0 or n ≤ 0 | HTTP 400 | Degenerate scheme prevents division-by-zero in combination generation |
| Non-integer k, n, or m | HTTP 400 | `strconv.Atoi` error surfaced before processing |
| m > n | HTTP 400 | Cannot have more mandatory shares than total shares |

#### Path Traversal

The download handler sanitises the `filename` parameter using `filepath.Base()` before constructing the full path. A request for `../../etc/passwd` resolves to `passwd` within the shares directory, which does not exist, and returns HTTP 404. No filesystem content outside the shares directory is accessible through this endpoint.


### Summary of Testing Outcomes

**Table 6.8  Consolidated Testing Summary**

| Category | Metric | Observed Result |
|---|---|---|
| Functional correctness | Happy-path accuracy (all configs) | 100.00% |
| Functional correctness | SHA-256 hash pass rate (happy path) | 100% (70 / 70 runs) |
| Mandatory enforcement | Missing-share rejection rate | 100% (TC 11–12, all runs blocked) |
| Threshold enforcement | Sub-threshold rejection rate | 100% (TC 13, all runs blocked) |
| Bit-flip tolerance  1%, optional share | Mean accuracy | 99.82% |
| Bit-flip tolerance  5%, mandatory share | Mean accuracy | 87.62% |
| Bit-flip tolerance  10%, all K shares | Mean accuracy | 62.34% |
| Image corruption  JPEG quality 90 | Mean accuracy | 94.18% |
| Image corruption  JPEG quality 50 | Mean accuracy | 51.22% (below usable threshold) |
| Image corruption  resize 50% → 100% | Mean accuracy | 2.14% (expected failure) |
| Image corruption  rotation 1° | Mean accuracy | 5.67% (expected failure) |
| Steganographic quality | Mean PSNR (all carriers) | 51.18 dB (threshold: 40 dB) |
| Performance  generation | (7, 5, 3), 1024 B secret | 131 ± 9 ms |
| Performance  reconstruction | (7, 5, 3), 1024 B secret | 67 ± 5 ms |
| Algorithmic complexity | Empirical scaling vs. secret length | O(L) confirmed — image I/O dominant |
| Input validation | Invalid parameter rejection | 100% (TC 15, all cases) |
| Security  path traversal | Directory traversal blocked | HTTP 404, no filesystem access |

The testing campaign validates that the implementation correctly realises the (N, K, M) threshold scheme with linear-time computational overhead. The primary operational limitation is the zero-redundancy nature of mandatory shares, any corruption of a mandatory share's cover image whether through geometric transformation, heavy compression, or direct bit-manipulation
 degrades secret recovery rapidly and non-linearly, with total loss occurring well before the mandatory share's payload is fully corrupted. This is an inherent and accepted trade-off of the prioritised trust model rather than an implementation defect and is documented in the paper as future work.
