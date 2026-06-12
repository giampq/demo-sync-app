# Demo TURN

Send `.zip` files **directly between two computers** on different networks — no
backend, no server holding your data.

- 🔒 **End-to-end encrypted (E2E)** — AES-GCM 256-bit, keys exchanged via ECDH P-256
- 🧩 **Chunked + dummy chunks + shuffled** locally before sending (anti-tracking)
- 🌐 **Direct browser-to-browser** over WebRTC — files travel device ↔ device
- 📄 **100% static** — only `html` / `css` / `js`, deploys straight to GitHub Pages

## How to use

One person **Creates the connection (Device A)**, the other **Joins (Device B)**:

1. **A** clicks *Create connection* → copies **your code** → sends it to B (via chat/email/anything).
2. **B** clicks *Join* → pastes A's code → clicks *Generate reply code* → copies the **reply code** → sends it back to A.
3. **A** pastes the reply code → *Finish connection*. ✅ The two devices connect directly.
4. Both pick a **folder** to save files into → drag-and-drop a `.zip` file to send.

> The code is exchanged **once** during the handshake. After that the data does
> not pass through any third party.

## Deploy to GitHub Pages

```bash
# create a new repo, then push: index.html, styles.css, app.js
git init && git add . && git commit -m "Demo TURN"
git branch -M main
git remote add origin https://github.com/<user>/<repo>.git
git push -u origin main
```

In the repo on GitHub: **Settings → Pages → Source = `main` / `(root)`**.
After ~1 minute, open `https://<user>.github.io/<repo>/`.

> **HTTPS is required** (GitHub Pages provides it). `crypto.subtle`, WebRTC and the
> folder picker do not work when opening the file via `file://`.

## Browser requirements

- **Chrome or Edge** (needs the File System Access API to write into a folder).
- WebRTC + WebCrypto (every modern browser has these).

## How the connection works

- **STUN** (Google, Cloudflare, freestun... — free, no signup) helps the two
  devices find a direct path through NAT. **STUN only finds a path; it does not
  relay data.**
- When the network is too strict (symmetric NAT / corporate firewall), it falls
  back to a **TURN relay**. The relay only sees encrypted data — it cannot read
  the contents.
- `ICE_SERVERS` in `app.js` lists **several free servers that back each other up** —
  the browser tries them and uses whichever works.

### Notes on TURN
- Free TURN with **no signup** is rare — currently using `freestun.net`
  (`free`/`free`), best-effort and may be congested.
- For a more reliable free TURN, **sign up for free** and paste the credentials
  into `ICE_SERVERS`:
  - **ExpressTURN** — free 1000 GB/month — https://www.expressturn.com/
  - **Metered Open Relay** — free tier — https://www.metered.ca/tools/openrelay/
- For **unlimited / high reliability** → run your own `coturn` on a VPS (bounded
  only by the VPS bandwidth), then swap it into `ICE_SERVERS`.
- Hourly-refreshed list of live STUN servers: https://github.com/pradt2/always-online-stun

### Caveats
- WebRTC exposes each device's **IP address to the other device** (inherent to a
  direct connection).
- The whole file is loaded into memory and all chunks are built before sending
  (required for shuffling). For very large files this uses a lot of RAM.
