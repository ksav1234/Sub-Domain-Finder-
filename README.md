 Subdomain Discovery Tool

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A powerful GUI-based subdomain discovery tool built with Python and PyQt5. This application helps security professionals, penetration testers, and developers find subdomains of target domains using DNS enumeration techniques.

## Features

- **Multi-threaded scanning** - Fast subdomain discovery with configurable thread counts
- **DNS resolution** - Customizable DNS servers for accurate results
- **HTTP/HTTPS validation** - Verify live web servers and get status codes
- **Export functionality** - Save results in CSV, JSON, or TXT formats
- **Dark/Light theme** - Toggle between light and dark mode
- **Real-time progress tracking** - Monitor scan progress with progress bar
- **Custom wordlist support** - Use built-in or import your own wordlists
- **Certificate Transparency logs** - Option to use CT logs for discovery
- **Common port checking** - Verify open ports on discovered subdomains

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Install Dependencies

```bash
# Install required packages
pip install PyQt5 dnspython requests
