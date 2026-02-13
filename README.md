# Py-IP-Range-Scanner

A modern, high-performance IP range scanner and generator written in Python. This tool is designed to efficiently scan large IP ranges using multi-threading, identify active hosts, and generate clean IP lists for various use cases.

## ✨ Key Features

* **Multi-Threaded Scanning:** Utilizes `ThreadPoolExecutor` for high-speed concurrent scanning of thousands of IPs.
* **Smart CIDR Handling:** intelligently expands CIDR ranges and includes safeguards against generating excessively large files. Supports adjustable range levels (**Short, Medium, Full**).
* **Multi-Protocol Support:** Capable of testing via **TCP, WebSocket (WS), HTTP, HTTPS, gRPC, QUIC, KCP, HTTPUpgrade, SplitHTTP, and xHTTP**.
* **Template System:** Pre-configured templates for popular providers like **Cloudflare** and **Fastly**, with support for custom templates in `settings.json`.
* **Checkpoints & Resume:** Stop long scans at any time and resume exactly where you left off.
* **Smart Generation:**
  * Generate IP ranges from Templates, File Input, or direct **Terminal Input**.
  * **Pre-Scan** option to filter reachable IPs before generating full ranges.
  * Automatic **Provider Tagging** in generated filenames and scan results.
* **Flexible Output:** Saves results in **JSON, CSV, and TXT**. Includes detailed metadata like Provider and Source.
* **Interactive TUI:** A user-friendly terminal interface for selected files, configuring scan settings, and managing output.
* **Dynamic Settings:** Change scan settings (like threads, timeout, port) *during* a scan by editing `settings.json`. The script detects changes and prompts to apply them in real-time.

## 📁 Project Structure

The project is organized into a clean and scalable structure to make navigation and modification intuitive.

```text
/
├── Config/         # Configuration files (settings.json)
├── Input/          # Directory for input files containing IP ranges
├── Output/         # Directory where scan results and generated ranges are saved
├── Checkpoints/    # Directory for scan checkpoints
├── main.py         # Main application entry point and logic
└── requirements.txt # List of Python dependencies
```

## ⚙️ How to Run the Project

To get a local copy up and running, follow these simple steps.

1. **Clone the repository:**

    ```sh
    git clone https://github.com/IMROVOID/Py-IP-Range-Scanner.git
    ```

2. **Navigate to the project directory:**

    ```sh
    cd Py-IP-Range-Scanner
    ```

3. **Install Dependencies (Requires Python 3):**

    ```sh
    pip install -r requirements.txt
    ```

4. **Run the application:**

    ```sh
    python main.py
    ```

    The interactive menu will appear in your terminal.

## 🔧 How to Modify the Project

This project was designed to be easily customizable. Here’s how you can modify its key parts:

* **Scanning Logic:** The core scanning and testing logic (TCP/HTTP/UDP) is located in the `IPTester` class within `main.py`.
* **Configuration:** You can adjust default timeouts, ports, threads, and **file update intervals** in `Config/settings.json`.
* **Range Levels:** Adjust the `ip_range_level` in settings to control how single IPs are expanded (Short=/24, Medium=/20, Full=/16).
* **Templates:** Add or remove IP range templates (e.g., for new CDNs) directly in `Config/settings.json`.

## 🛠️ Technologies & Libraries Used

This project leverages standard Python libraries and a few key packages for optimal performance.

| Library | Link | Description |
| :--- | :--- | :--- |
| **Python** | [python.org](https://www.python.org/) | The core programming language used. |
| **Requests** | [pypi.org/project/requests](https://pypi.org/project/requests/) | Simple, yet elegant HTTP library. |
| **Concurrent.futures** | [docs.python.org](https://docs.python.org/3/library/concurrent.futures.html) | Launching parallel tasks. |
| **Ipadress** | [docs.python.org](https://docs.python.org/3/library/ipaddress.html) | Manipulation of IPv4/IPv6 addresses. |

---

## 📜 License & Copyright

This project is completely open source and available to the public. You are free to use, modify, distribute, and fork this software for any purpose. No attribution is required, but it is appreciated.

---

## © About the Developer

This application was developed and is maintained by **Roham Andarzgou**.

I'm a passionate professional from Iran specializing in Graphic Design, Web Development, and cross-platform app development with Dart & Flutter. I thrive on turning innovative ideas into reality, whether it's a stunning visual, a responsive website, or a polished desktop app like this one. I also develop immersive games using Unreal Engine.

* **Website:** [rovoid.ir](https://rovoid.ir)
* **GitHub:** [IMROVOID](https://github.com/IMROVOID)
* **LinkedIn:** [Roham Andarzgou](https://www.linkedin.com/in/roham-andarzgouu)

### 🙏 Support This Project

If you find this application useful, please consider a donation. As I am based in Iran, cryptocurrency is the only way I can receive support. Thank you!

| Cryptocurrency | Address |
| :--- | :--- |
| **Bitcoin** (BTC) | `bc1qd35yqx3xt28dy6fd87xzd62cj7ch35p68ep3p8` |
| **Ethereum** (ETH) | `0xA39Dfd80309e881cF1464dDb00cF0a17bF0322e3` |
| **USDT** (TRC20) | `THMe6FdXkA2Pw45yKaXBHRnkX3fjyKCzfy` |
| **Solana** (SOL) | `9QZHMTN4Pu6BCxiN2yABEcR3P4sXtBjkog9GXNxWbav1` |
| **TON** | `UQCp0OawnofpZTNZk-69wlqIx_wQpzKBgDpxY2JK5iynh3mC` |
