<h1 align="center">
  <br>
  <a href="https://github.com/s0md3v/XSStrike"><img src="https://image.ibb.co/cpuYoA/xsstrike-logo.png" alt="xssniper"></a>
  <br>
  xssniper
  <br>
</h1>

<p align="center">
A maintained fork of <a href="https://github.com/s0md3v/XSStrike">XSStrike</a> focused on improving usability through configuration files, payload encoding, and a cleaner command-line interface.
</p>

---

## About

**xssniper** is a fork of **XSStrike**, a context-aware Cross-Site Scripting (XSS) scanner.

Unlike traditional scanners that inject static payload lists, xssniper analyzes how user input is reflected in the application's response, determines the execution context, evaluates server-side filtering, and generates payloads tailored to that context.

This fork preserves XSStrike's detection engine while introducing several usability improvements that make the tool easier to configure and use.

---

# Core Features

- Context-aware reflected XSS detection
- DOM XSS source/sink analysis
- Intelligent payload generation
- Reflection analysis and filter evaluation
- Multi-threaded website crawling
- WAF detection
- Blind XSS support
- Payload fuzzing
- Payload bruteforcing from custom wordlists

---

# New Features in xssniper

- Configuration files using YAML or JSON
- Configuration overlays with command-line precedence
- URL and Base64 payload encoding
- Improved command-line interface with grouped arguments

---

# Installation

```bash
git clone https://github.com/<your_username>/xssniper.git
cd xssniper

pip install -r requirements.txt
```

Run the scanner:

```bash
python xssniper.py
```

For backwards compatibility, the original entry point is still available:

```bash
python xsstrike.py
```

---

# Proof of Concept

## Reflected XSS Detection

The scanner analyzes reflections, identifies their execution context, generates payloads, and verifies which payloads successfully survive filtering.

```bash
python xssniper.py \
-u "https://public-firing-range.appspot.com/reflected/parameter/head?q=test"
```

Example output:

```text
[~] Checking for DOM vulnerabilities
[+] WAF Status: Offline
[!] Testing parameter: q
[!] Reflections found: 1
[~] Analysing reflections
[~] Generating payloads
[!] Payloads generated: 3072

------------------------------------------------------------

[+] Payload:
<d3v%09oNmOUseover%0d=%0d[8].find(confirm)>v3dm0s

[!] Efficiency: 100
[!] Confidence: 10
```

---

## DOM XSS Detection

The built-in DOM analyzer searches JavaScript for dangerous sources and sinks.

```bash
python xssniper.py \
-u https://public-firing-range.appspot.com/dom/toxicdom/localStorage/function/eval
```

Example output:

```text
[~] Checking for DOM vulnerabilities

[+] Potentially vulnerable objects found

------------------------------------------------------------

8    setTimeout(function() {

15   eval(payload);

19   eval(payload);

------------------------------------------------------------
```

---

## Website Crawling

The crawler recursively discovers pages, extracts forms, and performs DOM analysis throughout the crawl.

```bash
python xssniper.py \
--crawl \
-u https://public-firing-range.appspot.com/dom/index.html
```

Example output:

```text
[~] Crawling the target

[+] Potentially vulnerable objects found at
https://.../document/inputTyping/eval

4   eval(payload);

8   eval(payload);

25  eval(payload);

29  eval(payload);

...

[+] Potentially vulnerable objects found at
https://.../document/referrer/documentWrite

14  document.write(payload);

18  document.write(payload);
```

---

# Configuration Files

Scan settings can be stored in either YAML or JSON files.

Example (`xssniper.yaml`):

```yaml
timeout: 15
delay: 1
threadCount: 5
skipDOM: true
encode: url
```

Run:

```bash
python xssniper.py \
--config xssniper.yaml \
-u https://example.com/?q=test
```

Command-line arguments always override configuration file values.

Example:

```bash
python xssniper.py \
--config xssniper.yaml \
--timeout 5 \
-u https://example.com/?q=test
```

The scanner will use a timeout of **5 seconds**, even though the configuration file specifies a different value.

---

# Payload Encoding

Payloads can optionally be encoded before being sent to the target.

### URL Encoding

```bash
python xssniper.py \
-u https://example.com/?q=test \
--encode url
```

### Base64 Encoding

```bash
python xssniper.py \
-u https://example.com/?q=test \
--encode base64
```

This allows the scanner to test applications that decode user input before processing it.

---

# Command-Line Interface

The command-line interface has been reorganized into logical sections to make the tool easier to navigate.

```bash
python xssniper.py --help
```

The available options are grouped into:

- Target
- Mode
- Payloads & Encoding
- Network
- Crawling
- Miscellaneous

---

# Project Structure

```
core/
│── checker.py
│── generator.py
│── htmlParser.py
│── requester.py
│── ...

modes/
│── scan.py
│── crawl.py
│── bruteforcer.py
│── singleFuzz.py

plugins/
tests/
db/

xssniper.py
```

---

# Future Work

Potential future improvements include:

- Additional payload encoding methods
- Exporting scan results to structured formats
- Expanded automated test coverage
- Additional configuration options

---

# Credits

This project is based on the excellent work of **s0md3v** and the original **XSStrike** project.

This fork focuses on improving usability while preserving the original context-aware XSS detection engine.

---

# License

This project is licensed under the GNU GPL v3. See the `LICENSE` file for details.
