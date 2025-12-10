import json
import os
import sys
import subprocess

# ---------------- Vulnerable versions ----------------

VULN_REACT = ["19.0.0", "19.1.0", "19.1.1", "19.2.0"]

VULN_NEXT_RANGES = [
    ("15.0.0", "15.0.4"),
    ("15.1.0", "15.1.8"),
    ("15.2.0", "15.2.5"),
    ("15.3.0", "15.3.5"),
    ("15.4.0", "15.4.7"),
    ("15.5.0", "15.5.6"),
    ("16.0.0", "16.0.6"),
]

# ---------------- Version comparison ----------------

def parse_ver(v):
    return tuple(int(x) for x in v.split("."))

def version_in_range(ver, start, end):
    v = parse_ver(ver)
    return parse_ver(start) <= v <= parse_ver(end)

# ---------------- Helpers ----------------

def try_load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return None

# 1️⃣ Check node_modules/react/package.json
def version_from_node_modules(pkg):
    path = f"./node_modules/{pkg}/package.json"
    data = try_load_json(path)
    return data.get("version") if data else None

# 2️⃣ Check main project package.json dependencies
def version_from_package_json(pkg):
    data = try_load_json("./package.json")
    if not data:
        return None

    for section in ("dependencies", "devDependencies", "peerDependencies"):
        if section in data and pkg in data[section]:
            ver = data[section][pkg]
            return ver.lstrip("^~")  # remove ^ or ~
    return None

# 3️⃣ Check package-lock.json -> packages["node_modules/react"]
def version_from_package_lock(pkg):
    data = try_load_json("./package-lock.json")
    if not data:
        return None

    packages = data.get("packages", {})
    key = f"node_modules/{pkg}"

    if key in packages:
        return packages[key].get("version")

    return None

# 4️⃣ Run "npm list pkg --json"
def version_from_npm_list(pkg):
    try:
        out = subprocess.check_output(["npm", "list", pkg, "--json"], stderr=subprocess.STDOUT)
        data = json.loads(out.decode())
        deps = data.get("dependencies", {})
        if pkg in deps:
            return deps[pkg].get("version")
        return None
    except:
        return None

# 5️⃣ Run "next --version"
def version_from_next_cli():
    try:
        out = subprocess.check_output(["next", "--version"], stderr=subprocess.STDOUT)
        text = out.decode().strip()
        # Expected: "Next.js 15.2.3"
        parts = text.split()
        for p in parts:
            if p[0].isdigit():
                return p
        return None
    except:
        return None

# ---------------- Combined version resolver ----------------

def detect_version(pkg):
    methods = [
        version_from_node_modules,
        version_from_package_json,
        version_from_package_lock,
        version_from_npm_list
    ]

    if pkg == "next":
        methods.insert(0, lambda _: version_from_next_cli())

    for method in methods:
        try:
            ver = method(pkg)
            if ver:
                return ver
        except:
            pass

    return None

# ---------------- Vulnerability checks ----------------

def is_next_vulnerable(ver):
    if not ver:
        return False
    for start, end in VULN_NEXT_RANGES:
        if version_in_range(ver, start, end):
            return True
    return False

# ---------------- Main ----------------

def main():
    print("\n=== Local React / Next.js Vulnerability Scan ===\n")

    react_v = detect_version("react")
    next_v = detect_version("next")

    print(f"Detected React version: {react_v}")
    print(f"Detected Next.js version: {next_v}")

    print("\n--- Vulnerability Report ---")

    if react_v in VULN_REACT:
        print(f"[!] React {react_v} -> VULNERABLE")
    else:
        print(f"[OK] React {react_v} -> SECURE")

    if next_v and is_next_vulnerable(next_v):
        print(f"[!] Next.js {next_v} -> VULNERABLE")
    else:
        print(f"[OK] Next.js {next_v} -> SECURE")

    print("\n=== Scan Complete ===\n")


if __name__ == "__main__":
    main()
