# Mendix VAPT Scanner

A comprehensive, automated Vulnerability Assessment and Penetration Testing (VAPT) tool specifically optimized for Mendix applications, but capable of establishing a security baseline for any web architecture.

## Features

- **Mendix-Optimized**: Specifically checks for Mendix misconfigurations (unauthenticated `/xas/` access, exposed Client System).
- **11 Security Modules**: Includes coverage for XSS, CSRF, Cookie Security, Missing Headers, Auth/Access Control, Sensitive Data Exposure, and more.
- **Standalone Dashboard**: A beautiful, responsive web interface to run scans and view real-time progress.
- **Excel Reporting**: Instantly download professional, executive-ready Excel reports with color-coded severity matrices and remediation guides.
- **Universal Scanning**: While optimized for Mendix, the core modules can scan AWS, Azure, On-Premises, or Localhost environments for baseline vulnerabilities.

## How to Run

### Option 1: Standalone Windows Executable (.exe)
1. Download `mendix-vapt-scanner.exe` from the latest Releases.
2. Double-click the file to start the server.
3. Open your browser and navigate to `http://localhost:3000`.

### Option 2: Run via Node.js
If you prefer to run the source code directly:
1. Ensure you have Node.js (v18+) installed.
2. Clone this repository:
   ```bash
   git clone <repository_url>
   cd mendix-vapt-scanner
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start the application:
   ```bash
   npm start
   ```
5. Open your browser to `http://localhost:3000`.

## Disclaimer
This tool is intended for authorized security testing only. Please ensure you own or have explicit permission to scan the target environment.

## License
MIT License
