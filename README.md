# Py-IP-Range-Scanner

A modern, high-performance IP range scanner and generator written in Python. This tool is designed to efficiently scan large IP ranges using multi-threading, identify active hosts, and generate clean IP lists for various use cases.

## ✨ Key Features

* **Multi-Threaded Scanning:** Utilizes `ThreadPoolExecutor` for high-speed concurrent scanning of thousands of IPs.
* **Smart CIDR Handling:** intelligently expands CIDR ranges and includes safeguards against generating excessively large files. Supports adjustable range levels (**Short, Medium, Full**).
* **Multi-Protocol Support:** Capable of testing via **TCP, WebSocket (WS), HTTP, HTTPS, gRPC, QUIC, KCP, HTTPUpgrade, SplitHTTP, and xHTTP**.
* **Template System:** Pre-configured templates for popular providers like **Cloudflare**, **Fastly**, and **ArvanCloud**, with support for custom templates in `settings.json`.
* **Flexible Input:** robustly parses IPs/CIDRs from **JSON, TXT, CSV** or any raw text using regex. Supports nested JSON structures.
* **Checkpoints & Resume:** Stop long scans at any time and resume exactly where you left off.
* **Smart Generation:**
  * Generate IP ranges from Templates, File Input, or direct **Terminal Input**.
  * **Pre-Scan** option to filter reachable IPs before generating full ranges.
  * **Custom Tagging:** Prompts for optional **Custom Provider Name** to tag generated files.
* **Advanced Control:**
  * **Pause Menu:** Press `P` to pause, with options to modify settings (Global or Runtime) mid-scan.
  * **Dynamic Settings:** Change threading, timeout, etc., on the fly.
* **Flexible Output:** Saves results in **JSON, CSV, and TXT**. Includes detailed metadata like Provider and Source.
* **Interactive TUI:** A user-friendly terminal interface for selected files, configuring scan settings, and managing output.

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

## 📜 License

This project is open-source and licensed under the **[GNU General Public License v3.0 (GPL-3.0)](https://choosealicense.com/licenses/gpl-3.0/)**.

### Summary of Key Requirements

The GPL-3.0 is a strong copyleft license that ensures the software remains free. If you use, modify, or distribute this code, you must adhere to the following:

* **Disclose Source:** You must make the source code available when you distribute the software.
* **License & Copyright Notice:** You must include a copy of the license and the original author's copyright notice.
* **Same License (Copyleft):** Any modifications or derived works must also be licensed under GPL-3.0.
* **State Changes:** You must clearly indicate if you have modified the original files.
* **No Warranty:** This software is provided "as is" without any warranty of any kind.

> This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
>
> This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

For full details, please refer to the [LICENSE](/LICENSE) file in this repository.
