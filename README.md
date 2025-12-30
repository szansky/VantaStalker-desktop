# 🦇 VantaStalker

**Advanced Security Testing Toolkit** - A Burp Suite alternative written in Rust with an Egui-based GUI.

![Rust](https://img.shields.io/badge/Rust-1.70+-orange?logo=rust)
![License](https://img.shields.io/badge/License-MIT-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-green)

## ✨ Features

### 🔬 Core Proxy & Interception
- **HTTP/HTTPS Interception** - Pause, inspect, and modify requests/responses in real-time
- **Request Queue** - Handle multiple concurrent intercepted requests
- **Scope Filtering** - Auto-forward out-of-scope traffic
- **Site Map** - Visual tree structure of discovered endpoints

### 🧪 Security Scanners
| Scanner | Type | Description |
|---------|------|-------------|
| **Active Scanner** | Active | SQLi, XSS, Command Injection detection |
| **Passive Scanner** | Passive | Secrets, PII, Missing Headers, CORS, GraphQL |
| **JWT Analyzer** | Manual | Decode tokens, Attack with `alg:none` |
| **CORS Scanner** | Passive | Detect `ACAO: *` + Credentials, Null Origin |
| **GraphQL Scanner** | Passive | Endpoint detection via URL/Error patterns |
| **SSL/TLS Inspector** | Manual | Certificate validity, Issuer, Expiry check |

### 🚀 Offensive Tools
- **Repeater** - Manual request replay with syntax highlighting
- **Intruder** - High-performance fuzzer (Sniper, Pitchfork, Cluster Bomb)
- **Directory Fuzzer** - Multi-threaded content discovery (`/admin`, `.git`, etc.)
- **Crawler** - Automatic link extraction and spidering
- **Port Scanner** - TCP port scanning with service detection

### 🛠️ Utilities
- **Decoder** - Base64, URL, Hex, HTML encoding/decoding
- **Diffing** - Compare two responses side-by-side
- **Scripting Engine (Rhai)** - Custom request modification scripts
- **OAST Collaborator** - Out-of-band interaction detection
- **WebSocket Support** - Connect, send, and view WS messages

### 📊 Reporting & Persistence
- **Dashboard** - Real-time stats and charts
- **Project Save/Load** - SQLite-based persistence (`.vanta` files)
- **Export** - CSV, JSON, TXT, HTML reports
- **DNS Subdomain Enumeration** - Brute-force subdomains with wordlists

## 🚀 Quick Start

### Prerequisites
- **Rust** 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Node.js** 18+ (for Playwright CDP bridge)
- **OpenSSL** (for SSL Inspector)

### Installation
```bash
git clone https://github.com/szansky/VantaStalker-desktop.git
cd VantaStalker-desktop
npm install
./start.sh
```

## 📸 Screenshots

*Coming soon*

## 🏗️ Architecture

```
VantaStalker/
├── rust-app/           # Rust Core (Egui GUI + Logic)
│   ├── src/
│   │   ├── main.rs     # Entry point
│   │   ├── app.rs      # VantaApp state & event loop
│   │   ├── core/       # Business logic modules
│   │   └── ui/         # UI tab modules
│   └── Cargo.toml
├── src/                # Node.js CDP Bridge (Playwright)
│   └── index.ts
└── start.sh            # Launch script
```

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing`)
5. Open a Pull Request

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

Made with 🦀 by [@szansky](https://github.com/szansky)
