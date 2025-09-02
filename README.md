# SysX - Access. Execute. Monitor.

## 📌 Overview

`SysX` is a lightweight **Remote Monitoring & Management (RMM)** tool for internal networks.  
It allows administrators to **view remote screens**, **execute commands**, **browse files**, and **manage processes** through a clean web-based dashboard.

⚠️ **Important Notice:**  
This project is for **educational and internal demo purposes only**.  
Unauthorized use against systems you don’t own or manage is strictly prohibited.  
Do **not** upload the binaries to VirusTotal or public sandboxes.

---

## ✨ Features

- 🖥️ **Live Screen Streaming** – Real-time desktop view directly in the browser.  
- 💻 **Remote Shell** – Execute system commands (Linux: `sh`, Windows: `cmd`) with results streamed back.  
- ⚙️ **Process Management** – List, refresh, and terminate processes remotely.  
- 📂 **File Browser** – Explore directories, navigate drives, and securely download files.  
- 🔐 **Authentication** – Lightweight username/password login system.  
- 🌐 **Web Dashboard** – Professional interface, accessible from the index page.  

---

## Download from Release - [SysX](https://github.com/malwarekid/SysX/releases)

---

## 🎥 Demo

https://github.com/user-attachments/assets/618a9659-255d-4694-8cc3-8e9f1f4e0dd1

---

## 🚀 Getting Started

### 1️⃣ Build the Server (Operator Side)
```bash
go build -ldflags="-w -s" -o sysx server.go
````

Run the server:

```bash
./sysx
```
---

### 2️⃣ Build the Client (Target Side)

Build the agent binary:

```bash
go build -ldflags="-w -s" -o agent client.go
```

Run the client on the target system:

```bash
./agent
```

The client will automatically connect to the server and start streaming.

---

### 3️⃣ Access the Dashboard

Open your browser and go to:

```
http://localhost:8080
```

Default credentials:

* **Username:** `admin`
* **Password:** `malwarekid`

---

## ⚒️ Cross-Compiling

You can build binaries for multiple platforms:

**Linux (from any OS):**

```bash
GOOS=linux GOARCH=amd64 go build -o agent-linux client.go
```

**Windows (from Linux/macOS):**

```bash
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -o agent.exe client.go
```

**macOS:** (Not Tested)

```bash
GOOS=darwin GOARCH=amd64 go build -o agent-macos client.go
```

---

## ⚙️ Requirements

* **Server:** Go 1.20+
* **Clients:**

  * Linux (X11 required for screen capture)
  * Windows (tested on Windows 10/11)

**Networking:**

* Ensure port `8080` is open and accessible (configure firewall rules if necessary).

---

## 📂 Project Structure

```
SysX - Access. Execute. Monitor.

├── client.go        # Agent (runs on remote system)
├── server.go        # Central server with web dashboard
├── templates/       # HTML templates for UI
│   ├── index.html
│   ├── login.html
│   ├── viewer.html
│   ├── shell.html
│   ├── processes.html
│   └── files.html
├── go.mod           # Go module definition
└── go.sum           # Dependency checksums

```

---

## 📝 License

Released under the **MIT License**.
See the [LICENSE](https://github.com/malwarekid/SysX/blob/main/LICENSE) file.

---

## 👤 Credits

Developed by [Malwarekid](https://github.com/malwarekid)

Follow:

* 🐙 [Author](https://github.com/malwarekid)
* 📷 [Instagram](https://instagram.com/malwarekid)
* 📧 [Linkedin](https://github.com/malwarekid)

---

## ⚠️ Disclaimer

This tool is intended strictly for **authorized use in internal environments**.
The author assumes **no liability** for misuse or damages caused by this software.
