## 3. Project Planning (4-Month Timeline)

We planned the whole project in a span of around 4 months. Because it was a team of five people, we divided the work according to what each one is good at. But honestly, sometimes we had to re-divide because someone got stuck or had exams. So the timeline below is what we mostly followed, though there were small delays here and there.

### Month 1 - Literature Survey & Tech Stack Finalisation

**Week 1-2:** We started by reading papers on secret sharing - specially the BNB scheme because our supervisor told us it has linear property. Also looked at encryption algorithms like AES, ChaCha20 and chaos based logistic map. We found that chaos is interesting but not many people use it, so we thought why not try both.

**Week 3-4:** Finalised the tools. Decided to use Go (Golang) for the backend because it's fast and handles concurrency well. For the web part we chose Gin framework. Also planned to use LSB steganography for embedding shares into images. We made a small prototype to check if Go can handle the bitwise operations fast enough - it worked fine.

### Month 2 - Core Implementation (BNB + Encryption)

**Week 5-6:** Implemented the BNB secret sharing logic - generating combinations, building the mask matrix, and creating the shares. This was the hardest part because the research paper wasn't super clear. We had to read it many times and also write some test cases to verify the reconstruction (OR operation). After around 10 days we got it right.

**Week 7-8:** Added the two ciphers - ChaCha20 and the chaos logistic map. For chaos we had to carefully tune the logistic map parameters (r and x0) so that the keystream is really random. Also we added a SHA256 hash to verify integrity. We then integrated the crypto layer with the BNB layer. By the end of month 2, the command-line version was working.

### Month 3 - Web Interface & Steganography

**Week 9-10:** Built the Gin web server with endpoints for generating shares and reconstructing secret. Also wrote the HTML/CSS frontend (basic, nothing fancy). We added the option to upload a carrier image or use a default one. The LSB embedding function was written and tested with PNG images.

**Week 11-12:** Implemented the extraction part - reading the LSB bits from uploaded images, checking mandatory flag, and then reconstructing. We faced a bug where the length header sometimes overflowed, but we fixed it by using 32 bits. Also added download links for the share images. By the end of week 12, the whole web application was running on localhost.

### Month 4 - Testing, Deployment & Documentation

**Week 13-14:** We deployed the application on AWS EC2 (t2.micro instance) to test in a real environment. Did integrity testing - tried different (k, n, m) combinations, different cipher choices, and also tried to corrupt some shares to see if reconstruction fails correctly. Found a small issue with the chaos decryption when the seed length varied, but we corrected it.

**Week 15-16:** Wrote the project report, prepared the presentation, and made the flow diagrams. Also we recorded a demo video showing the generate and reconstruct process. The last week was for fixing formatting and submitting.

### Summary

| Month | Tasks |
|-------|-------|
| Month 1 | Literature survey, paper reading, tech stack finalisation, small prototype |
| Month 2 | BNB core logic, ChaCha20 + chaos encryption, crypto layer integration |
| Month 3 | Gin web server, frontend, steganography embed/extract, local testing |
| Month 4 | AWS deployment, integrity testing, bug fixes, documentation & report writing |

**Note:** We actually overshooted by a few days in month 2 because the mask generation took longer than expected. But we compensated by working extra on weekends. Overall the project was completed within 4 months as planned.
