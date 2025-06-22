# SysX (Trial Version - Linux Only)

## Overview

`SysX` is a powerful remote administration and monitoring tool designed for internal network use. It allows authorized administrators to **view screens**, **execute shell commands**, and **manage processes** remotely. This trial release is a compiled binary **only for Linux systems**.

⚠️ **This trial is for educational or internal demo use only. Do not upload this binary to VirusTotal or other public sandboxes.**

---

## Features

- 🖥️ **Live Screen Viewing** – Real-time streaming of connected clients.
- 💻 **Remote Shell Access** – Execute commands and see the output in a web interface.
- ⚙️ **Process Management** – List running processes and terminate them as needed.
- 🔐 **Simple Auth** – Lightweight username/password-based login.
- 🌐 **Web UI** – Custom HTML/CSS frontend with a retro terminal theme.

---

## Download from Release - [SysX-Trial](https://github.com/malwarekid/SysX-Trial/releases)

---

## Demo

https://github.com/user-attachments/assets/c83044c5-775a-45ca-9257-517f071710f7

---

## Getting Started

1. **Extract the release files:**

    ```bash
    unzip SysX-Trial.tar.gz && cd SysX
    ```

2. **Run the server:**

    ```bash
    ./sysx
    ```

3. **Run the client (on target system):**

    ```bash
    ./agent
    ```

    > You can copy the client binary to any Linux machine in the same network.

4. **Access the dashboard:**

    Open your browser and navigate to:

    ```
    http://localhost:8080
    ```

    > Default credentials:
    - **Username:** admin
    - **Password:** followmalwarekid

---

## Requirements

- Linux (x86_64)
- Compatible desktop environment for screen capture (X11)
- Port `8080` open on host for web access

---

## License

This trial version is released under the **MIT License**. See the [LICENSE](LICENSE) file.

---

## Credits

Developed and designed by [Malwarekid](https://github.com/malwarekid)

Follow:
- 🐙 [GitHub](https://github.com/malwarekid)
- 📷 [Instagram](https://instagram.com/malwarekid)

---

## ⚠️ Disclaimer

This software is provided **as-is** for demo/testing purposes. It must **not** be used against systems without proper authorization. The authors are **not responsible** for any misuse or damage caused.

