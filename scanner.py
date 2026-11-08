
import datetime
import html
import socket
import ssl
from urllib.parse import urlparse

import requests

# ============================================================
# AO WEB SCANNER - WEB SECURITY ASSESSMENT TOOL
# Scan only websites and systems that you own or are authorized
# to assess.
# ============================================================

DARK_BLUE = "\033[38;2;0;35;100m"
RESET = "\033[0m"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-Proxy",
}

results = []

# ============================================================
# LARGE ASCII TITLE + GHOST ICON
# ============================================================

BIG_FONT = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "N": ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "W": ["10001", "10001", "10001", "10101", "10101", "10101", "01010"],
    " ": ["00000"] * 7,
}

GHOST_ART = [
    '     .-""".',
    "   ." + " " * 9 + "'.",
    '  /  .-. .-  \\',
    ' |  | x x |  |',
    ' |  |  ^  |  |',
    ' |  |     |  |',
    '  \\  ' + "_" * 7 + "  /",
]


def render_big_text(text):
    """Render text using a built-in 5x7 block font."""
    text = text.upper()
    rendered_lines = []

    for row in range(7):
        pieces = []

        for character in text:
            pattern = BIG_FONT.get(
                character, BIG_FONT[" "]
            )[row]

            pieces.append(
                "".join(
                    "█" if bit == "1" else " "
                    for bit in pattern
                )
            )

        rendered_lines.append("  ".join(pieces).rstrip())

    return rendered_lines


def show_banner():

    print(DARK_BLUE)
    print("=" * 76)
    print()

    for line in render_big_text("AO WEB"):
        print("   " + line)

    print()

    scanner_lines = render_big_text("SCANNER")

    for index, line in enumerate(scanner_lines):
        ghost = GHOST_ART[index]
        print("   " + line + "     " + ghost)

    print()
    print(
        "                 WEB SECURITY ASSESSMENT TOOL  |  VERSION 2"
    )
    print("=" * 76)
    print(RESET)


# ============================================================
# RESULT STORAGE
# ============================================================

def add_result(test, status, details):

    results.append({
        "test": test,
        "status": status,
        "details": str(details),
    })


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(url):

    url = url.strip()

    if not url:
        raise ValueError("Please enter a website URL.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            "Invalid URL. Use a valid http:// or https:// address."
        )

    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError("Invalid port in website URL.") from error

    return url, parsed


# ============================================================
# DNS INFORMATION
# ============================================================

def scan_dns(host):

    print("\n[+] DNS INFORMATION")

    try:
        addresses = socket.getaddrinfo(host, None)

        ips = sorted({
            item[4][0] for item in addresses
        })

        add_result(
            "DNS Resolution",
            "PASS",
            ", ".join(ips)
        )

        for ip in ips:
            print("[OK] IP Address:", ip)

    except socket.gaierror:

        add_result(
            "DNS Resolution",
            "FAILED",
            "Could not resolve hostname"
        )

        print("[FAILED] Could not resolve hostname")


# ============================================================
# HTTP SECURITY HEADERS
# ============================================================

def scan_headers(response):

    print("\n[+] SECURITY HEADERS")

    for header in SECURITY_HEADERS:

        if header in response.headers:

            print("[OK]", header)

            add_result(
                header,
                "PASS",
                "Header detected"
            )

        else:

            print("[WARNING]", header, "Missing")

            add_result(
                header,
                "WARNING",
                "Security header is missing"
            )


# ============================================================
# SERVER INFORMATION
# ============================================================

def scan_server(response):

    print("\n[+] SERVER INFORMATION")

    server = response.headers.get(
        "Server",
        "Not disclosed"
    )

    print("Server:", server)

    add_result(
        "Server Information",
        "INFO",
        server
    )


# ============================================================
# SSL / TLS CHECK
# ============================================================

def scan_ssl(host, port):

    print("\n[+] SSL / TLS CHECK")

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port),
            timeout=5
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=host
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                tls_version = secure_socket.version() or "Unknown"

                expiry_text = certificate.get("notAfter")

                if not expiry_text:
                    raise ValueError(
                        "Certificate expiry date was not provided"
                    )

                expiry = datetime.datetime.strptime(
                    expiry_text,
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=datetime.timezone.utc)

                now = datetime.datetime.now(
                    datetime.timezone.utc
                )

                remaining = (expiry - now).days

                print("TLS Version:", tls_version)
                print("Certificate Expiry:", expiry.isoformat())
                print("Days remaining:", remaining)

                if remaining >= 0:

                    add_result(
                        "SSL Certificate",
                        "PASS",
                        f"Valid. Expires: {expiry.isoformat()} "
                        f"({remaining} days remaining)"
                    )

                else:

                    add_result(
                        "SSL Certificate",
                        "WARNING",
                        f"Certificate has expired: {expiry.isoformat()}"
                    )

                add_result(
                    "TLS Version",
                    "INFO",
                    tls_version
                )

    except Exception as error:

        add_result(
            "SSL Certificate",
            "WARNING",
            str(error)
        )

        print("[WARNING] SSL/TLS check failed:", error)


# ============================================================
# COOKIE SECURITY
# ============================================================

def scan_cookies(response):

    print("\n[+] COOKIE SECURITY")

    cookies = response.cookies

    if not cookies:

        add_result(
            "Cookies",
            "INFO",
            "No cookies detected"
        )

        print("No cookies found")
        return

    for cookie in cookies:

        flags = []

        if cookie.secure:
            flags.append("Secure")

        if cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("HttpOnly")

        if cookie.has_nonstandard_attr("SameSite"):
            flags.append("SameSite")

        details = (
            ", ".join(flags)
            if flags
            else "Security flags missing"
        )

        status = "PASS" if len(flags) == 3 else "WARNING"

        add_result(
            "Cookie: " + cookie.name,
            status,
            details
        )

        print(cookie.name + ":", details)


# ============================================================
# COMMON PORT CHECK
# ============================================================

def scan_ports(host):

    print("\n[+] COMMON PORT CHECK")
    print("Checking common TCP ports on the authorized target...")

    for port, service in COMMON_PORTS.items():

        try:

            with socket.create_connection(
                (host, port),
                timeout=0.6
            ):

                print("[OPEN]", port, service)

                add_result(
                    f"Port {port} - {service}",
                    "INFO",
                    "Open"
                )

        except (OSError, TimeoutError):

            print("[CLOSED/FILTERED]", port, service)

            add_result(
                f"Port {port} - {service}",
                "INFO",
                "Closed or filtered"
            )


# ============================================================
# HTML REPORT GENERATOR
# ============================================================

def generate_report(url):

    filename = "security_report.html"

    warning_count = sum(
        1 for item in results
        if item["status"] == "WARNING"
    )

    if warning_count == 0:
        risk = "LOW"

    elif warning_count <= 3:
        risk = "MEDIUM"

    else:
        risk = "HIGH"

    rows = ""

    for item in results:

        rows += f"""
        <tr>
            <td>{html.escape(item['test'])}</td>
            <td>{html.escape(item['status'])}</td>
            <td>{html.escape(item['details'])}</td>
        </tr>
        """

    scan_date = datetime.datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    report = f"""
    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">

        <meta name="viewport"
              content="width=device-width, initial-scale=1.0">

        <title>AO Web Scanner - Security Assessment Report</title>

        <style>

            body {{
                font-family: Arial, sans-serif;
                background: #f1f4f9;
                padding: 30px;
                color: #172554;
            }}

            .container {{
                background: white;
                padding: 25px;
                border-radius: 10px;
                max-width: 1100px;
                margin: auto;
                box-shadow: 0 4px 18px rgba(0, 0, 0, 0.08);
            }}

            h1 {{
                color: #002364;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                overflow-wrap: anywhere;
            }}

            th, td {{
                border: 1px solid #ddd;
                padding: 12px;
                text-align: left;
            }}

            th {{
                background: #002364;
                color: white;
            }}

            tr:nth-child(even) {{
                background: #f2f2f2;
            }}

            .risk {{
                font-size: 22px;
                font-weight: bold;
            }}

            .footer {{
                color: #64748b;
                margin-top: 25px;
            }}

        </style>

    </head>

    <body>

        <div class="container">

            <h1>AO Web Scanner</h1>

            <p>
                <b>Website:</b>
                {html.escape(url)}
            </p>

            <p>
                <b>Scan Date:</b>
                {html.escape(scan_date)}
            </p>

            <p class="risk">
                Risk Indicator: {html.escape(risk)}
            </p>

            <p>
                <b>Warnings detected:</b>
                {warning_count}
            </p>

            <h2>Security Assessment Results</h2>

            <table>

                <tr>
                    <th>Test</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>

                {rows}

            </table>

            <p class="footer">
                Educational security assessment report.
                Results are not a full penetration test.
            </p>

        </div>

    </body>
    </html>
    """

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(report)

    print("\n[+] Report saved:", filename)


# ============================================================
# MAIN SCANNER FUNCTION
# ============================================================

def scan_website(url):

    results.clear()

    url, parsed = validate_url(url)

    host = parsed.hostname

    port = parsed.port or (
        443 if parsed.scheme == "https" else 80
    )

    print("\nConnecting to:", url)

    scan_dns(host)

    try:

        response = requests.get(
            url,
            timeout=10,
            verify=True,
            allow_redirects=True,
            headers={
                "User-Agent": "AO-Web-Scanner/2.0"
            },
        )

        print("\n[+] HTTP STATUS:", response.status_code)

        add_result(
            "HTTP Status",
            "INFO",
            response.status_code
        )

        scan_headers(response)

        scan_server(response)

        scan_cookies(response)

    except requests.RequestException as error:

        add_result(
            "HTTP Connection",
            "FAILED",
            error
        )

        print("[FAILED] Connection Error:", error)

    if parsed.scheme == "https":

        scan_ssl(host, port)

    scan_ports(host)

    generate_report(url)

    print("\n========== SCAN COMPLETED ==========")

    print(
        "Open security_report.html in your browser to view the report."
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    show_banner()

    print(
        "Use this scanner only on websites you own "
        "or have permission to test."
    )

    target = input(
        "\n[+] Enter website URL: "
    ).strip()

    try:

        scan_website(target)

    except ValueError as error:

        print("\n[!] Invalid URL:", error)

    except KeyboardInterrupt:

        print("\n[!] Scan cancelled by user.")

    except Exception as error:

        print("\n[!] Unexpected Error:", error)
