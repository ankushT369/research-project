## Conclusion
So after all the implementation and testing we can say the project works as we wanted. The main thing we achieved is that mandatory shares are actually mandatory — you cannot recover the secret without all of them, even if you have enough total shares. Our functional tests (TC 1-10) gave 100% accuracy every time, which was good to see.

From the fault tolerance tests we learned some important stuff. Bit flips on optional shares at 5% corruption still gave around 98% accuracy, but the same corruption on a mandatory share dropped accuracy to 87% because mandatory bits have no redundancy. When we corrupted all 5 shares at 10% bit-flip rate, accuracy fell to 62% due to OR saturation false positives. So mandatory shares are powerful but also fragile.

The image corruption tests showed what we expected — JPEG at quality 90 was okay (94% accuracy), but quality 50 killed it (51%). Rotation or resizing destroyed everything because LSB embedding is not geometrically robust. So PNG must stay lossless.

Performance was fine; generation for (7,5,3) with 1KB secret took about 131ms and reconstruction 67ms. PSNR was around 51dB, which is well above the 40dB imperceptibility threshold.

One limitation we already knew: the chaos cipher is experimental only, not for real use. Also, the mandatory flag is self-reported, so an attacker could fake it, but the crypto layer would still fail because the actual secret bits would be wrong.

Overall, the system meets our goal of priority-based secret sharing with linear time complexity. It is not perfect for every scenario, but for use cases like legal escrow or military chain of command where mandatory approvals are required, it works well. Testing confirmed both the strengths (threshold enforcement, integrity checks) and the weaknesses (mandatory share fragility, no geometric robustness). Future work could add error correction or use a more robust steganography method.
