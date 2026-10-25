#!/usr/bin/env python3
"""Felix Fons Campus Service Mapper: offline, read-only Linux inventory.

Python 3.8+; no third-party dependencies.
"""

import argparse
import datetime as dt
import glob
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

SAFE_NAME = re.compile(r"^[A-Za-z0-9*_.@-]{1,160}$")
SAFE_ROUTE = re.compile(r"^[A-Za-z0-9/_.*~^$=+?-]{1,120}$")
SAFE_IMAGE = re.compile(r"^[A-Za-z0-9*_.@:-]{1,160}$")
SAFE_TARGET = re.compile(r"^[A-Za-z0-9_.:-]{1,180}$")
MAX_RECORDS = 500
ADVISORY_SNAPSHOT = "2026-10-25"
PROJECT_CONTACT = "Felix Fons | https://felixfons.ru | +7 917 410-87-48"
PHP_FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
NODE_FIXED = {(22,): (22, 23, 4), (24,): (24, 22, 1), (26,): (26, 12, 1)}


def numeric_version(value):
    match = re.search(r"(?<!\d)(\d{1,2})\.(\d{1,3})(?:\.(\d{1,3}))?", value or "")
    return tuple(int(x or 0) for x in match.groups()) if match else None


def security_findings(report):
    """Offline triage candidates. Never equate CLI/config evidence with a live app."""
    findings = []

    def add(priority, observed, risk, verify, source):
        findings.append({"priority": priority, "observed": observed,
                         "possible_risk": risk, "verify_before_enable": verify,
                         "source": source})

    php_source = "https://www.php.net/archive/2026.php"
    php_versions = []
    for pool in report.get("php_pools", []):
        version = numeric_version(pool.get("php_version_from_config_path"))
        if version:
            php_versions.append(("путь конфигурации PHP-FPM, пул " + pool.get("pool", "?"), version, False))
    cli_php_text = report.get("versions_cli_only", {}).get("php_cli") or ""
    cli_php = numeric_version(cli_php_text)
    if cli_php:
        php_versions.append(("PHP CLI", cli_php,
                             bool(re.search(r"\b\d+\.\d+\.\d+\b", cli_php_text))))
    for box in report.get("containers", []):
        tag = box.get("image_tag") or ""
        match = re.match(r"^php:(\d+\.\d+(?:\.\d+)?)", tag, re.I)
        if match:
            version = numeric_version(match.group(1))
            if version:
                php_versions.append(("метка образа контейнера " + box.get("name", "?") +
                                     " (" + str(box.get("state") or "состояние неизвестно") + ")",
                                     version, match.group(1).count(".") == 2))
    seen = set()
    for evidence, version, has_patch in php_versions:
        key = (evidence, version)
        if key in seen:
            continue
        seen.add(key)
        branch = version[:2]
        if branch <= (8, 1):
            add("высокий", evidence + " указывает " + ".".join(map(str, version)),
                "Ветка PHP не поддерживается проектом PHP; исправления могут быть у поставщика ОС.",
                "Установить версию именно работающего веб-процесса и наличие исправлений поставщика; до проверки не публиковать.",
                "https://www.php.net/supported-versions.php")
        elif has_patch and branch in PHP_FIXED and version[2] < PHP_FIXED[branch]:
            add("критический", evidence + " указывает " + ".".join(map(str, version)),
                "Версия ниже выпуска, который закрыл две критические ошибки с возможностью удалённого выполнения кода; поставщик ОС мог выпустить отдельное исправление.",
                "Уточнить версию работающего PHP, проверить исправления поставщика ОС; при необходимости обновить и перезапустить процесс обработки запросов.",
                php_source)
        elif not has_patch and branch in PHP_FIXED:
            add("проверка", evidence + " указывает ветку " + ".".join(map(str, branch)),
                "По этому признаку известна только ветка PHP; номер исправления и версия работающего процесса неизвестны.",
                "Установить полную версию работающего PHP-FPM и сверить с бюллетенем и патчами поставщика.",
                php_source)
        elif branch > (8, 5):
            add("проверка", evidence + " указывает " + ".".join(map(str, version)),
                "Ветка не охвачена этим снимком правил; статус выпуска нужно проверить отдельно.",
                "Проверить официальный статус ветки и версию работающего веб-процесса.", php_source)
    if php_versions:
        add("проверка", "Найдены признаки установленного PHP", 
            "Для части конфигураций остаётся отдельное условное предупреждение по session upload progress.",
            "Проверить действующее значение session.upload_progress.enabled=0 до включения PHP-сервисов; также проверить приложения и версию работающего процесса.",
            php_source)
    for signal in report.get("php_setting_signals", []):
        if signal.get("configured") in ("on", "unrecognized"):
            add("высокий", "В " + signal.get("config_kind", "конфигурации") +
                " ветки PHP " + str(signal.get("php_branch") or "?") +
                " параметр session.upload_progress.enabled = " + signal["configured"],
                "При особом сочетании кода и настроек остаётся риск из информационного бюллетеня PHP; применимость не установлена.",
                "Проверить действующее значение в процессе обработки веб-запросов, выключить параметр согласно бюллетеню и перезапустить процесс.",
                php_source)

    node = numeric_version(report.get("versions_cli_only", {}).get("node_cli"))
    if node and (node[0] < 22 or node[0] in (23, 25)):
        add("высокий", "Node CLI = " + ".".join(map(str, node)),
            "Эта ветка завершила поддержку проекта Node.js; использование веб-приложением не установлено.",
            "Определить версию запущенного приложения и план перехода на поддерживаемую ветку.",
            "https://nodejs.org/en/about/previous-releases")
    elif node and (node[0],) in NODE_FIXED and node < NODE_FIXED[(node[0],)]:
        add("высокий", "Node CLI = " + ".".join(map(str, node)),
            "CLI ниже октябрьского выпуска безопасности; версия веб-процесса неизвестна.",
            "Определить версию запущенного приложения или контейнера и обновить его при необходимости.",
            "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases")
    for box in report.get("containers", []):
        tag = box.get("image_tag") or ""
        match = re.match(r"^node:(\d+)(?:\.(\d+))?(?:\.(\d+))?", tag, re.I)
        if match:
            version = tuple(int(x or 0) for x in match.groups())
            if version[0] < 22 or version[0] in (23, 25):
                add("высокий", "Метка образа контейнера " + box.get("name", "?") + " указывает Node " + tag,
                    "Метка указывает на ветку без поддержки; фактическая версия внутри образа не проверена.",
                    "Проверить образ по идентификатору и работающий процесс; перейти на поддерживаемый выпуск.",
                    "https://nodejs.org/en/about/previous-releases")
            elif match.group(2) and match.group(3) and (version[0],) in NODE_FIXED and version < NODE_FIXED[(version[0],)]:
                add("высокий", "Метка образа контейнера " + box.get("name", "?") + " указывает Node " + tag,
                    "Метка ниже октябрьского выпуска безопасности; фактический образ может отличаться от метки.",
                    "Проверить идентификатор образа и версию работающего процесса, затем обновить образ.",
                    "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases")

    nginx = numeric_version(report.get("versions_cli_only", {}).get("nginx"))
    if nginx and (nginx < (1, 30, 6) or (1, 31, 0) <= nginx < (1, 31, 7)):
        add("проверка", "nginx CLI = " + ".".join(map(str, nginx)),
            "Версию нужно сверить с бюллетенями разработчика; применимость зависит от настроек и исправлений поставщика ОС.",
            "Проверить версию работающего nginx, исправления поставщика ОС и условия каждой опубликованной ошибки; один номер версии не доказывает уязвимость.",
            "https://nginx.org/en/security_advisories.html")

    for command_name in ("apache2", "httpd"):
        apache = numeric_version(report.get("versions_cli_only", {}).get(command_name))
        if apache and apache[:2] == (2, 4) and apache < (2, 4, 69):
            add("проверка", "Apache HTTP Server CLI = " + ".".join(map(str, apache)),
                "В выпуске 2.4.69 исправлены опубликованные ошибки. Их применимость зависит от модулей и исправлений поставщика ОС.",
                "Проверить версию работающего Apache, включённые модули и бюллетень поставщика ОС.",
                "https://httpd.apache.org/security/vulnerabilities_24.html")

    database_ports = {3306, 5432, 6379, 27017, 9200}
    mapped_ports = set()
    for site in report.get("nginx_vhosts", []) + report.get("apache_vhosts", []):
        mapped_ports.update(site.get("listen", []))
        for route in site.get("routes", []):
            if route.get("scope") == "loopback" and route.get("port"):
                mapped_ports.add(route["port"])
    for item in report.get("listeners", []):
        if item.get("port") in database_ports and item.get("bind") == "all_interfaces":
            add("высокий", "Порт " + str(item["port"]) + " слушает на всех интерфейсах",
                "Сервис данных может быть доступен за пределами нужной сети; firewall/NAT неизвестны.",
                "Проверить ACL, firewall и внешний маршрут; ограничить доступ по назначению перед публикацией.", "локальное наблюдение")
        elif (item.get("bind") == "all_interfaces" and item.get("port") not in mapped_ports
              and item.get("port") not in (22,)):
            add("проверка", "Порт " + str(item["port"]) +
                " слушает на всех интерфейсах, но явной связи с найденными веб-маршрутами нет",
                "Назначение порта и доступность извне неизвестны.",
                "Установить владельца процесса и необходимость порта; проверить firewall/NAT до включения.",
                "локальное наблюдение")
    for process in report.get("listener_processes_private", []):
        if process.get("deleted_executable"):
            add("высокий", "Работающий процесс " + str(process.get("executable") or "?") +
                " на портах " + ", ".join(map(str, process.get("ports", []))) +
                " использует удалённый с диска исполняемый файл",
                "После обновления может продолжать работать старый бинарный код.",
                "Подтвердить пакет и версию процесса; спланировать контролируемый перезапуск после копии и проверки отката.",
                "локальное наблюдение")
    return findings[:MAX_RECORDS]


def run(argv, timeout=5, max_chars=200000):
    if not shutil.which(argv[0]):
        return None, "команда не найдена"
    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=False)
        if done.returncode:
            return None, "команда завершилась с ошибкой или нет доступа"
        return done.stdout[:max_chars], None
    except (OSError, subprocess.TimeoutExpired):
        return None, "команда недоступна или истекло время ожидания"


def clean(value, pattern=SAFE_NAME):
    value = value.strip().strip('"\'')
    return value if pattern.fullmatch(value) else None


def bind_scope(address):
    address = address.strip("[]")
    if address in ("127.0.0.1", "::1", "localhost"):
        return "loopback"
    if address in ("0.0.0.0", "::", "*"):
        return "all_interfaces"
    return "specific_interface"


def host_port(value):
    # urlsplit removes URL userinfo; host is retained only in the private JSON.
    value = value.split("?", 1)[0].strip()
    host = None
    port = None
    if value.startswith(("https://", "http://")):
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            pass
    elif not value.startswith("unix:"):
        token = value.split("/", 1)[0]
        if token.startswith("[") and "]:" in token:
            host, raw_port = token[1:].split("]:", 1)
            port = int(raw_port) if raw_port.isdigit() else None
        elif ":" in token:
            host, raw_port = token.rsplit(":", 1)
            port = int(raw_port) if raw_port.isdigit() else None
        else:
            host = token
    host = clean(host or "", SAFE_TARGET)
    if port is not None and not 1 <= port <= 65535:
        port = None
    socket_id = None
    if "unix:" in value or value.startswith("unix:"):
        scope = "unix_socket"
        socket_path = value.split("unix:", 1)[1].split(";", 1)[0]
        socket_id = hashlib.sha256(socket_path.encode("utf-8")).hexdigest()[:12]
    elif host in ("127.0.0.1", "localhost", "::1"):
        scope = "loopback"
    elif host and ("$" in value):
        scope = "dynamic_unresolved"
        host = None
    elif host:
        scope = "named_or_remote"
    else:
        scope = "unresolved"
    return {"scope": scope, "port": port, "target_host": host, "socket_id": socket_id}


def local_addresses():
    raw, error = run(["ip", "-j", "address", "show"])
    if error:
        return []
    try:
        interfaces = json.loads(raw)
    except ValueError:
        return []
    result = set()
    for interface in interfaces:
        for addr in interface.get("addr_info", []):
            try:
                result.add(str(ipaddress.ip_address(addr.get("local", ""))))
            except ValueError:
                pass
    return sorted(result)


def parse_listeners(raw):
    found = []
    for line in raw.splitlines()[:MAX_RECORDS]:
        parts = line.split()
        if len(parts) < 5:
            continue
        endpoint = parts[3]
        m = re.search(r":(\d{1,5})$", endpoint)
        if not m:
            continue
        port = int(m.group(1))
        if not 1 <= port <= 65535:
            continue
        address = endpoint[:m.start()]
        proc = re.search(r'users:\(\("([^" ]+)', line)
        name = clean(proc.group(1)) if proc else None
        item = {"port": port, "bind": bind_scope(address), "process": name}
        if item not in found:
            found.append(item)
    return sorted(found, key=lambda x: (x["port"], x["bind"]))


def listener_processes(raw):
    """Map listener PID to executable basename; never read process arguments or env."""
    found = {}
    for line in raw.splitlines()[:MAX_RECORDS]:
        port_match = re.search(r":(\d{1,5})\s", line)
        if not port_match:
            continue
        port = int(port_match.group(1))
        for pid_text in re.findall(r"\bpid=(\d{1,9})\b", line):
            pid = int(pid_text)
            item = found.setdefault(pid, {"pid": pid, "ports": set(),
                                          "executable": None, "deleted_executable": False})
            item["ports"].add(port)
    result = []
    for pid, item in list(found.items())[:200]:
        try:
            target = os.readlink("/proc/" + str(pid) + "/exe")
            item["deleted_executable"] = target.endswith(" (deleted)")
            base_path = target[:-len(" (deleted)")] if item["deleted_executable"] else target
            item["executable"] = clean(Path(base_path).name)
        except OSError:
            pass
        item["ports"] = sorted(item["ports"])
        result.append(item)
    return result


def nginx_files(warnings):
    pending = []
    for pattern in ("/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf"):
        pending.extend(glob.glob(pattern))
    found = set()
    while pending and len(found) < MAX_RECORDS:
        path = pending.pop(0)
        if path in found or not Path(path).is_file():
            continue
        found.add(path)
        data = read_config(path, warnings)
        if data is None:
            continue
        for match in re.finditer(r"^\s*include\s+([^;\s]+);", data, re.M):
            spec = match.group(1)
            if "$" in spec:
                continue
            include_pattern = spec if os.path.isabs(spec) else os.path.join("/etc/nginx", spec)
            pending.extend(glob.glob(include_pattern)[:MAX_RECORDS])
    if pending:
        warnings.append("Часть включаемых файлов nginx пропущена из-за лимита записей")
    return sorted(found)


def read_config(path, warnings):
    try:
        file = Path(path)
        if file.stat().st_size > 1024 * 1024:
            warnings.append("Слишком большой файл конфигурации пропущен: " + (clean(file.name) or "неизвестно"))
            return None
        return file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        warnings.append("Файл конфигурации недоступен: " + (clean(Path(path).name) or "неизвестно"))
        return None


def parse_upstreams(text):
    result = {}
    name = None
    depth = 0
    for original in text.splitlines():
        line = original.split("#", 1)[0].strip()
        start = re.match(r"upstream\s+([A-Za-z0-9_.-]+)\s*\{", line)
        if name is None and start:
            name = clean(start.group(1))
            depth = 0
            if name:
                result.setdefault(name, [])
        if name is None:
            continue
        depth += line.count("{") - line.count("}")
        server = re.match(r"server\s+([^;\s]+)", line)
        if server:
            result[name].append(host_port(server.group(1)))
        if depth <= 0:
            name = None
    return result


def parse_nginx_text(text, source):
    # Whitelist only routing directives. Ignore all other config, including secrets.
    entries, current = [], None
    depth = 0
    location_depth = None
    for original in text.splitlines():
        line = original.split("#", 1)[0].strip()
        if not line:
            continue
        if current is None and re.match(r"^server\s*\{", line):
            current = {"source": source, "names": [], "listen": [], "routes": []}
            depth = 0
            location_depth = None
        if current is None:
            continue
        depth += line.count("{") - line.count("}")
        if location_depth is not None and depth < location_depth:
            current.pop("route_context", None)
            location_depth = None
        m = re.match(r"server_name\s+(.+?);", line)
        if m:
            for name in m.group(1).split():
                safe = clean(name)
                if safe and safe != "_" and safe not in current["names"]:
                    current["names"].append(safe)
        m = re.match(r"listen\s+([^;]+);", line)
        if m:
            token = m.group(1).split()[0]
            hp = host_port(token) if ":" in token else None
            port = hp["port"] if hp else (int(token) if token.isdigit() else None)
            if port and port not in current["listen"]:
                current["listen"].append(port)
        location = re.match(r"location\s+(?:[=~*^]+\s+)?([^\s{]+)", line)
        if location:
            route = clean(location.group(1), SAFE_ROUTE)
            current["route_context"] = route
            location_depth = depth
        target = re.match(r"(proxy_pass|fastcgi_pass)\s+([^;]+);", line)
        if target:
            current["routes"].append({"path": current.get("route_context") or "/",
                                      "kind": target.group(1), **host_port(target.group(2))})
        if depth <= 0:
            current.pop("route_context", None)
            entries.append(current)
            current = None
    return entries


def nginx_inventory(warnings):
    entries = []
    upstreams = {}
    certificate_paths = []
    for path in nginx_files(warnings):
        data = read_config(path, warnings)
        if data is None:
            continue
        entries.extend(parse_nginx_text(data, Path(path).name))
        upstreams.update(parse_upstreams(data))
        certificate_paths.extend(re.findall(r"^\s*ssl_certificate\s+([^;\s]+);", data, re.M))
    if not entries:
        warnings.append("Локальные сайты nginx не найдены; для связи с публичными адресами нужна карта узла входа")
    return entries[:MAX_RECORDS], upstreams, certificate_paths


def apache_inventory(warnings):
    paths = sorted(set(glob.glob("/etc/apache2/apache2.conf") +
                       glob.glob("/etc/apache2/sites-enabled/*") +
                       glob.glob("/etc/httpd/conf/httpd.conf") +
                       glob.glob("/etc/httpd/conf.d/*.conf")))[:MAX_RECORDS]
    entries, certificate_paths = [], []
    for path in paths:
        data = read_config(path, warnings)
        if data is None:
            continue
        current = None
        for original in data.splitlines():
            line = original.split("#", 1)[0].strip()
            start = re.match(r"<VirtualHost\s+([^>]+)>", line, re.I)
            if start:
                m = re.search(r":(\d{1,5})", start.group(1))
                current = {"source": Path(path).name, "names": [],
                           "listen": [int(m.group(1))] if m else [], "routes": []}
                continue
            if current is None:
                continue
            if re.match(r"</VirtualHost>", line, re.I):
                entries.append(current)
                current = None
                continue
            names = re.match(r"(?:ServerName|ServerAlias)\s+(.+)$", line, re.I)
            if names:
                for name in names.group(1).split():
                    safe = clean(name)
                    if safe and safe not in current["names"]:
                        current["names"].append(safe)
            proxy = re.match(r"ProxyPass\s+(\S+)\s+(\S+)", line, re.I)
            if proxy:
                path_name = clean(proxy.group(1), SAFE_ROUTE)
                if path_name:
                    current["routes"].append({"path": path_name, "kind": "ProxyPass",
                                              **host_port(proxy.group(2))})
            cert = re.match(r"SSLCertificateFile\s+(\S+)", line, re.I)
            if cert:
                certificate_paths.append(cert.group(1))
    return entries[:MAX_RECORDS], certificate_paths


def certificate_inventory(paths):
    result = []
    for path in sorted(set(paths))[:MAX_RECORDS]:
        if "$" in path or not Path(path).is_file():
            continue
        raw, error = run(["openssl", "x509", "-in", path, "-noout",
                          "-dates", "-ext", "subjectAltName"])
        if error:
            continue
        dates = dict(re.findall(r"^(notBefore|notAfter)=(.+)$", raw, re.M))
        names = re.findall(r"DNS:([A-Za-z0-9*_.-]+)", raw)[:50]
        result.append({"names": names,
                       "not_before": dates.get("notBefore"),
                       "not_after": dates.get("notAfter")})
    return result


def php_pool_inventory(warnings):
    pools = []
    for path in sorted(glob.glob("/etc/php/*/fpm/pool.d/*.conf"))[:MAX_RECORDS]:
        data = read_config(path, warnings)
        if data is None:
            continue
        version_match = re.search(r"/etc/php/([^/]+)/fpm/", path)
        version = clean(version_match.group(1)) if version_match else None
        pool_match = re.search(r"^\s*\[([^]]+)\]", data, re.M)
        pool = clean(pool_match.group(1)) if pool_match else Path(path).stem
        listen_match = re.search(r"^\s*listen\s*=\s*([^\s;]+)", data, re.M)
        if pool and listen_match:
            target = listen_match.group(1)
            if target.startswith("/"):
                endpoint = {"scope": "unix_socket", "port": None, "target_host": None,
                            "socket_id": hashlib.sha256(target.encode("utf-8")).hexdigest()[:12]}
            else:
                endpoint = host_port(target)
            pools.append({"pool": pool, "php_version_from_config_path": version,
                          "listen": endpoint})
    return pools


def php_setting_signals(warnings):
    """Read one allowlisted setting, not arbitrary PHP configuration values."""
    patterns = ("/etc/php/*/fpm/php.ini", "/etc/php/*/apache2/php.ini",
                "/etc/php/*/fpm/pool.d/*.conf")
    result = []
    for pattern in patterns:
        for path in sorted(glob.glob(pattern))[:MAX_RECORDS]:
            data = read_config(path, warnings)
            if data is None:
                continue
            version_match = re.search(r"/etc/php/([^/]+)/", path)
            branch = clean(version_match.group(1)) if version_match else None
            for line in data.splitlines():
                if line.lstrip().startswith((";", "#")):
                    continue
                match = re.match(r"\s*(?:php_(?:admin_)?(?:value|flag)\[)?session\.upload_progress\.enabled\]?\s*=\s*([^;#\s]+)", line, re.I)
                if not match:
                    continue
                value = match.group(1).lower()
                state = ("off" if value in ("0", "off", "false", "no") else
                         "on" if value in ("1", "on", "true", "yes") else "unrecognized")
                result.append({"php_branch": branch, "config_kind": "pool" if "/pool.d/" in path else "php.ini",
                               "setting": "session.upload_progress.enabled", "configured": state})
    return result[:MAX_RECORDS]


def services(warnings):
    result = []
    for scope, prefix in (("system", []), ("user", ["--user"])):
        raw, error = run(["systemctl", *prefix, "list-units", "--type=service", "--all",
                          "--plain", "--no-legend", "--no-pager"])
        if error:
            if scope == "system":
                warnings.append("Список служб systemd недоступен: " + error)
            continue
        for line in raw.splitlines()[:MAX_RECORDS]:
            parts = line.lstrip("● ").split()
            if len(parts) >= 4 and parts[0].endswith(".service"):
                name = clean(parts[0])
                if name:
                    result.append({"name": name, "scope": scope, "load": parts[1],
                                   "active": parts[2], "sub": parts[3]})
    return result


def service_unit_files(warnings):
    result = []
    for scope, prefix in (("system", []), ("user", ["--user"])):
        raw, error = run(["systemctl", *prefix, "list-unit-files", "--type=service",
                          "--all", "--plain", "--no-legend", "--no-pager"])
        if error:
            if scope == "system":
                warnings.append("Файлы служб systemd недоступны: " + error)
            continue
        rows = raw.splitlines()
        if len(rows) > MAX_RECORDS:
            warnings.append("Список файлов служб systemd обрезан по лимиту")
        for line in rows[:MAX_RECORDS]:
            parts = line.split()
            if len(parts) >= 2 and parts[0].endswith(".service"):
                name = clean(parts[0])
                state = clean(parts[1])
                if name and state:
                    result.append({"name": name, "scope": scope, "unit_file_state": state})
    return result


def docker_inventory(warnings):
    # Pin the local Unix socket: DOCKER_HOST/context may otherwise point off-host.
    docker_local = ["docker", "--host", "unix:///var/run/docker.sock"]
    raw, error = run([*docker_local, "ps", "--all", "--no-trunc", "--format", "{{json .}}"])
    if error:
        warnings.append("Список локальных контейнеров Docker недоступен: " + error)
        return []
    result = []
    ids = []
    for line in raw.splitlines()[:MAX_RECORDS]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        name = clean(item.get("Names", ""))
        image = item.get("Image", "").split("/")[-1]
        image = clean(image, SAFE_IMAGE)
        if not name:
            continue
        container_id = item.get("ID", "")
        if re.fullmatch(r"[a-f0-9]{12,64}", container_id):
            ids.append(container_id)
        ports = []
        for bind, port in re.findall(r"(?:(127\.0\.0\.1|0\.0\.0\.0|::):)?(\d{1,5})->", item.get("Ports", "")):
            ports.append({"port": int(port), "bind": bind_scope(bind or "*")})
        state = clean(item.get("State", ""))
        result.append({"name": name, "image_tag": image, "image_id": None, "state": state,
                       "published_ports": ports,
                       "health": None, "restarts": None, "addresses": []})
    if ids:
        # Docker's Go template limits output to selected fields, excluding Env and mounts.
        template = "{{.Name}}|{{.RestartCount}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}|{{.Image}}|{{json .NetworkSettings.Networks}}"
        details, error = run([*docker_local, "inspect", "--format", template, *ids[:100]], timeout=12)
        if not error:
            by_name = {x["name"]: x for x in result}
            for line in details.splitlines():
                parts = line.split("|", 4)
                if len(parts) != 5:
                    continue
                target = by_name.get(parts[0].lstrip("/"))
                if target is None:
                    continue
                target["restarts"] = int(parts[1]) if parts[1].isdigit() else None
                target["health"] = clean(parts[2])
                if re.fullmatch(r"sha256:[a-f0-9]{64}", parts[3]):
                    target["image_id"] = parts[3]
                try:
                    networks = json.loads(parts[4]) or {}
                except ValueError:
                    continue
                addresses = []
                for details in networks.values():
                    for key in ("IPAddress", "GlobalIPv6Address"):
                        try:
                            addresses.append(str(ipaddress.ip_address(details.get(key, ""))))
                        except ValueError:
                            pass
                target["addresses"] = sorted(set(addresses))
    return result


def journal_error_summary():
    result, categories = {}, {}
    known = {
        "нет места на диске": r"no space left on device|disk full",
        "нехватка памяти": r"out of memory|oom-kill|cannot allocate memory",
        "отказ доступа": r"permission denied|access denied",
        "нет соединения с зависимостью": r"connection refused|connection timed out|network is unreachable",
        "ошибка сертификата": r"certificate (?:has )?expired|unable to get local issuer certificate",
        "авария процесса": r"segmentation fault|core dumped|signal 11",
    }
    for scope, prefix in (("system", []), ("user", ["--user"])):
        raw, error = run(["journalctl", *prefix, "--since", "24 hours ago", "-p", "err",
                          "-n", "300", "--no-pager", "--output=json"], timeout=6)
        if error:
            continue
        for line in raw.splitlines()[:300]:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            unit = clean(event.get("_SYSTEMD_UNIT", "") or event.get("_SYSTEMD_USER_UNIT", ""))
            if unit:
                key = scope + ":" + unit
                result[key] = result.get(key, 0) + 1
                message = str(event.get("MESSAGE", ""))[:2000].lower()
                for label, pattern in known.items():
                    if re.search(pattern, message):
                        group = categories.setdefault(key, {})
                        group[label] = group.get(label, 0) + 1
    return dict(sorted(result.items())), dict(sorted(categories.items()))


def backup_indicators(services_list):
    words = ("backup", "snapshot", "dump", "restic", "borg", "bacula", "duplicity")
    found = []
    for service in services_list:
        if any(word in service["name"].lower() for word in words):
            found.append({"type": "service_name", "name": service["name"]})
    for path in sorted(glob.glob("/etc/cron.d/*"))[:MAX_RECORDS]:
        name = Path(path).name
        if clean(name) and any(word in name.lower() for word in words):
            found.append({"type": "cron_filename", "name": name})
    return found


def tunnel_inventory(services_list, warnings):
    active = {(x["scope"], x["name"]) for x in services_list if x["active"] == "active"}
    paths = (glob.glob("/etc/systemd/system/*.service") +
             glob.glob("/etc/systemd/system/*/*.service") +
             glob.glob(str(Path.home() / ".config/systemd/user/*.service")))
    result = []
    for path in sorted(set(paths))[:MAX_RECORDS]:
        data = read_config(path, warnings)
        if data is None:
            continue
        unit = clean(Path(path).name)
        scope = "user" if "/.config/systemd/user/" in path else "system"
        for direction, spec in re.findall(r"(?:^|\s)-([RL])\s+([^\s;]+)", data):
            pieces = spec.split(":")
            if len(pieces) == 4:
                bind, listen_port, target, target_port = pieces
            elif len(pieces) == 3:
                listen_port, target, target_port = pieces
                bind = "localhost"
            else:
                continue
            if not (listen_port.isdigit() and target_port.isdigit()):
                continue
            if not (1 <= int(listen_port) <= 65535 and 1 <= int(target_port) <= 65535):
                continue
            target = clean(target, SAFE_TARGET)
            if unit and target:
                result.append({"unit": unit, "active": (scope, unit) in active,
                               "direction": direction, "listen_port": int(listen_port),
                               "listen_bind": bind_scope(bind), "target_host": target,
                               "target_port": int(target_port)})
    return result


def software_versions():
    commands = {"nginx": ["nginx", "-v"], "apache2": ["apache2", "-v"],
                "httpd": ["httpd", "-v"], "php_cli": ["php", "-v"],
                "node_cli": ["node", "--version"], "docker_cli": ["docker", "--version"],
                "mysql_cli": ["mysql", "--version"], "psql_cli": ["psql", "--version"]}
    result = {}
    for name, argv in commands.items():
        if not shutil.which(argv[0]):
            continue
        try:
            done = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                                  timeout=3, check=False)
            first = (done.stdout or done.stderr).splitlines()[0]
            # Whitelist version text; never pass through arbitrary errors or environment.
            if re.fullmatch(r"[A-Za-z0-9 ._()/,+:-]{1,140}", first):
                result[name] = first
        except (OSError, subprocess.TimeoutExpired, IndexError):
            pass
    return result


def package_versions(warnings):
    """Installed package identifiers for vendor advisory checks; no package changelogs."""
    if shutil.which("dpkg-query"):
        raw, error = run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"],
                         timeout=10, max_chars=1000000)
        manager = "dpkg"
    elif shutil.which("rpm"):
        raw, error = run(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"],
                         timeout=10, max_chars=1000000)
        manager = "rpm"
    else:
        return {"manager": None, "selected": [], "all": []}
    if error:
        warnings.append("Версии установленных пакетов недоступны: " + error)
        return {"manager": manager, "selected": [], "all": []}
    result = []
    all_packages = []
    wanted = re.compile(r"^(?:nginx(?:[-:].*)?|apache2(?:[-:].*)?|httpd(?:[-:].*)?|php(?:[0-9.]*)(?:[-:].*)?|nodejs(?:[-:].*)?|openssl(?:[-:].*)?|docker(?:[-:].*)?|containerd(?:[-:].*)?)$", re.I)
    for line in raw.splitlines()[:5000]:
        pieces = line.split("\t", 1)
        if len(pieces) != 2:
            continue
        name, version = pieces
        if (re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,120}", name) and
                re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}", version)):
            item = {"package": name, "version": version}
            all_packages.append(item)
            if wanted.fullmatch(name):
                result.append(item)
    if len(raw.splitlines()) >= 5000 or len(raw) >= 1000000:
        warnings.append("Список установленных пакетов может быть неполным")
    return {"manager": manager, "selected": result[:200], "all": all_packages}


def disk_root():
    raw, error = run(["df", "-P", "/"])
    if error or len(raw.splitlines()) < 2:
        return None
    parts = raw.splitlines()[-1].split()
    return parts[4] if len(parts) >= 5 and re.fullmatch(r"\d{1,3}%", parts[4]) else None


def distribution():
    try:
        data = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    values = {}
    for key in ("ID", "VERSION_ID", "PRETTY_NAME"):
        match = re.search(r"^" + key + r"=(.+)$", data, re.M)
        if match:
            safe = clean(match.group(1), re.compile(r"[A-Za-z0-9 ._()/-]{1,100}"))
            if safe:
                values[key.lower()] = safe
    return values


def collect():
    warnings = []
    if (dt.datetime.now(dt.timezone.utc).date() - dt.date.fromisoformat(ADVISORY_SNAPSHOT)).days > 7:
        warnings.append("Снимок бюллетеней старше семи дней; перед решением о включении проверьте свежие официальные публикации")
    raw, error = run(["ss", "-H", "-lntp"])
    if error:
        warnings.append("Список слушающих портов недоступен: " + error)
    nginx_sites, upstreams, nginx_certs = nginx_inventory(warnings)
    apache_sites, apache_certs = apache_inventory(warnings)
    service_list = services(warnings)
    journal_counts, journal_categories = journal_error_summary()
    report = {
        "schema": 1,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": clean(socket.gethostname()) or "unknown",
        "os": platform.system() + " " + platform.release(),
        "distribution": distribution(),
        "access": "current user; incomplete where permissions deny reads",
        "local_addresses": local_addresses(),
        "disk_root_used": disk_root(),
        "versions_cli_only": software_versions(),
        "installed_packages": package_versions(warnings),
        "listeners": parse_listeners(raw or ""),
        "listener_processes_private": listener_processes(raw or ""),
        "services": service_list,
        "service_unit_files": service_unit_files(warnings),
        "containers": docker_inventory(warnings),
        "nginx_vhosts": nginx_sites,
        "nginx_upstreams": upstreams,
        "apache_vhosts": apache_sites,
        "php_pools": php_pool_inventory(warnings),
        "php_setting_signals": php_setting_signals(warnings),
        "certificates": certificate_inventory(nginx_certs + apache_certs),
        "journal_errors_24h": journal_counts,
        "journal_categories_24h": journal_categories,
        "backup_indicators": backup_indicators(service_list),
        "tunnels": tunnel_inventory(service_list, warnings),
        "warnings": sorted(set(warnings)),
        "not_checked": ["user accounts", "database contents", "backup integrity",
                        "application login", "remote availability", "raw log review",
                        "certificate chain as served to clients", "firewall/NAT outside this host"],
    }
    report["security_triage"] = security_findings(report)
    return report


def resolve_target(source, route, reports, seen_upstreams=None):
    target = route.get("target_host")
    port = route.get("port")
    if target and target in source.get("nginx_upstreams", {}):
        seen_upstreams = seen_upstreams or set()
        if target in seen_upstreams:
            return "циклическая настройка upstream; связь не определена"
        members = source["nginx_upstreams"][target]
        if len(members) == 1:
            return resolve_target(source, members[0], reports, seen_upstreams | {target})
        return "группа upstream (" + str(len(members)) + " узлов); проверить каждый"
    if route.get("scope") == "unix_socket":
        match = next((pool for pool in source.get("php_pools", [])
                      if pool["listen"].get("socket_id") == route.get("socket_id")), None)
        if match:
            return "локальный пул PHP-FPM " + match["pool"] + " (совпадение по конфигурации; процесс не проверен)"
        return "локальный Unix-сокет; процесс не сопоставлен"
    if not target and not port:
        return "динамическое или неизвестное направление"
    candidates = []
    if route.get("scope") == "loopback":
        candidates = [source]
    elif target:
        for report in reports:
            if target == report.get("host") or target in report.get("local_addresses", []):
                candidates.append(report)
            elif any(target in box.get("addresses", []) for box in report.get("containers", [])):
                candidates.append(report)
    if not candidates:
        return "целевой сервер не найден среди обследованных узлов"
    report = candidates[0]
    label = report.get("host", "unknown")
    if port is None:
        return label + "; целевой порт неизвестен"
    if report is source and route.get("scope") == "loopback":
        remote_forwards = [(other, tunnel) for other in reports for tunnel in other.get("tunnels", [])
                           if tunnel.get("direction") == "R" and tunnel.get("active") and
                           tunnel.get("listen_port") == port and other is not source]
        if len(remote_forwards) == 1:
            other, tunnel = remote_forwards[0]
            target_port = tunnel["target_port"]
            has_listener = any(item.get("port") == target_port for item in other.get("listeners", []))
            return (other.get("host", "unknown") + ":" + str(target_port) +
                    " (связь по конфигурации обратного туннеля; локальный слушатель " +
                    ("наблюдался" if has_listener else "не наблюдался") + ")")
        if len(remote_forwards) > 1:
            return "несколько обратных туннелей подходят к этому порту; связь не определена"
    listener = any(item.get("port") == port for item in report.get("listeners", []))
    container = any(port in [p.get("port") for p in box.get("published_ports", [])]
                    for box in report.get("containers", []))
    if listener or container:
        return label + ":" + str(port) + " (слушатель наблюдался; работа сервиса не проверена)"
    return label + ":" + str(port) + " (слушатель не наблюдался)"


def md_cell(value):
    return str(value if value is not None else "не определено").replace("|", "\\|").replace("\n", " ")


def bind_label(value):
    return {"all_interfaces": "все интерфейсы", "loopback": "только локально",
            "specific_interface": "отдельный интерфейс"}.get(value, value or "не определено")


def markdown(reports):
    lines = ["# Felix Fons — карта сервисов (предварительная)", "",
             "Данные собраны локально без сетевых запросов и изменений. Это инвентаризация, а не заключение о безопасности.", "",
             "| Сервер | Время UTC | Дистрибутив | Службы | Контейнеры | Порты | Веб-сайты | Диск / |",
             "|---|---|---|---:|---:|---:|---:|---:|"]
    for r in reports:
        lines.append("| " + " | ".join(map(md_cell, [r.get("host"), r.get("collected_at"),
                     r.get("distribution", {}).get("pretty_name"),
                     len(r.get("services", [])), len(r.get("containers", [])),
                     len(r.get("listeners", [])), len(r.get("nginx_vhosts", [])) + len(r.get("apache_vhosts", [])),
                     r.get("disk_root_used")])) + " |")
    lines += ["", "## Публичные имена и локальные зависимости", "",
              "| Сервер | Имя сайта | Порт входа | Путь | Куда направляет |",
              "|---|---|---:|---|---|"]
    rows = []
    for r in reports:
        for site in r.get("nginx_vhosts", []) + r.get("apache_vhosts", []):
            for name in site.get("names", []):
                routes = site.get("routes") or [{"path": "/", "kind": "static_or_unmapped", "scope": "not_mapped", "port": None}]
                for route in routes:
                    rows.append([r["host"], name, ", ".join(map(str, site.get("listen", []))) or "?",
                                 route.get("path"), resolve_target(r, route, reports)])
    for row in sorted(rows)[:MAX_RECORDS]:
        lines.append("| " + " | ".join(map(md_cell, row)) + " |")
    if not rows:
        lines.append("| — | Не удалось прочитать конфигурацию веб-сервера | — | — | Требуется доступ администратора |")
    lines += ["", "## Слушающие порты", "",
              "Адрес интерфейса и PID не выводятся. Привязка ко всем интерфейсам не доказывает доступ из интернета: сеть и межсетевой экран проверяются отдельно.", "",
              "| Сервер | Порт | Привязка | Процесс |", "|---|---:|---|---|"]
    for r in reports:
        for item in r.get("listeners", [])[:100]:
            lines.append("| " + " | ".join(map(md_cell, [r["host"], item.get("port"),
                                                        bind_label(item.get("bind")), item.get("process")])) + " |")
    lines += ["", "## Обратные туннели к локальным сервисам", "",
              "Здесь видна лишь конфигурация туннеля. Публичное имя устанавливается при объединении с отчётом узла входа.", "",
              "| Сервер | Служба туннеля | Активна | Порт на входном узле | Локальный порт | Локальный слушатель |",
              "|---|---|---|---:|---:|---|"]
    tunnel_rows = 0
    for r in reports:
        local_ports = {item.get("port") for item in r.get("listeners", [])}
        for tunnel in r.get("tunnels", []):
            if tunnel.get("direction") != "R":
                continue
            tunnel_rows += 1
            lines.append("| " + " | ".join(map(md_cell, [r.get("host"), tunnel.get("unit"),
                         "да" if tunnel.get("active") else "нет", tunnel.get("listen_port"),
                         tunnel.get("target_port"),
                         "наблюдался" if tunnel.get("target_port") in local_ports else "не наблюдался"])) + " |")
    if not tunnel_rows:
        lines.append("| — | Обратные туннели не найдены | — | — | — | — |")
    lines += ["", "## Установленные файлы служб", "",
              "Показаны службы с типичными для веб-приложений именами. Полный список находится в закрытом JSON; disabled сам по себе не означает неисправность.", ""]
    related = re.compile(r"nginx|apache|httpd|php|mysql|mariadb|postgres|docker|containerd|node|portal|web|app|gunicorn|uwsgi|redis", re.I)
    for r in reports:
        matches = [x for x in r.get("service_unit_files", []) if related.search(x.get("name", ""))]
        for item in matches[:100]:
            lines.append("- " + md_cell(r["host"]) + ": " + md_cell(item["name"]) +
                         " — " + md_cell(item["unit_file_state"]))
        if not matches:
            lines.append("- " + md_cell(r["host"]) + ": типичные имена не найдены или список недоступен")
    lines += ["", "## Контейнеры, включая остановленные", "",
              "| Сервер | Контейнер | Состояние | Образ | Опубликованные порты | Health | Рестарты |",
              "|---|---|---|---|---|---|---:|"]
    for r in reports:
        for box in r.get("containers", [])[:100]:
            ports = ", ".join(str(p["port"]) + " (" + bind_label(p["bind"]) + ")"
                              for p in box.get("published_ports", [])) or "нет"
            lines.append("| " + " | ".join(map(md_cell, [r["host"], box.get("name"), box.get("state"),
                                                        box.get("image_tag"), ports,
                                                        box.get("health"), box.get("restarts")])) + " |")
    lines += ["", "## Обнаруженные версии CLI", "",
              "Это версии запускаемых утилит, а не подтверждение версии конкретного сайта.", ""]
    for r in reports:
        versions = "; ".join(k + " = " + v for k, v in r.get("versions_cli_only", {}).items())
        lines.append("- " + md_cell(r["host"]) + ": " + md_cell(versions or "нет данных"))
    lines += ["", "## Версии установленных пакетов", "",
              "Номера пакетов нужны для проверки исправлений поставщика ОС. Наличие пакета не доказывает, что сайт использует его.", ""]
    for r in reports:
        packages = r.get("installed_packages", {}).get("selected", [])
        values = "; ".join(item["package"] + "=" + item["version"] for item in packages)
        lines.append("- " + md_cell(r["host"]) + ": " + md_cell(values or "нет данных"))
    lines += ["", "## Приоритеты проверки безопасности", "",
              "Офлайн-сверка по снимку официальных бюллетеней на " + ADVISORY_SNAPSHOT + ". Это кандидаты для проверки, а не подтверждённые CVE в работающем сервисе. Сведения поставщика ОС и версии процессов нужно сверить отдельно.", "",
              "Как читать: «критический» и «высокий» означают, что проверку следует поставить в начало очереди; «проверка» означает недостаток данных для вывода. Ни одна метка не доказывает уязвимость или взлом.", "",
              "| Сервер | Приоритет | Подтверждённое наблюдение | Вероятный риск | Что проверить до включения | Источник |",
              "|---|---|---|---|---|---|"]
    triage_count = 0
    for r in reports:
        for finding in r.get("security_triage") or security_findings(r):
            lines.append("| " + " | ".join(map(md_cell, [r.get("host"), finding["priority"],
                         finding["observed"], finding["possible_risk"],
                         finding["verify_before_enable"], finding["source"]])) + " |")
            triage_count += 1
    if not triage_count:
        lines.append("| — | — | Автоматических совпадений нет | Безопасность не установлена | Проверить каждый сервис вручную | — |")
    lines += ["", "## Порядок возврата каждого сервиса", "",
              "Для каждого публичного имени отдельно отметить: ответственный и назначение; маршрут до приложения; версия работающего процесса и исправления поставщика; резервная копия с пробным восстановлением; вход и права пользователей; сертификат в сетевом ответе; журналы и основные сценарии; наблюдение после включения и способ отката. Для сервисов с учётными записями отдельно проверить вход и роли. Пустой результат сборщика не закрывает ни один пункт. Включать по одному сервису после ручного решения ответственного."]
    lines += ["", "## Требует внимания", ""]
    any_issue = False
    for r in reports:
        failed = [x["name"] for x in r.get("services", []) if x["active"] == "failed"]
        if failed:
            lines.append("- " + md_cell(r["host"]) + ": сбой служб — " + ", ".join(failed[:30]))
            any_issue = True
        for box in r.get("containers", []):
            if box.get("state") in ("running", "restarting") and (
                    box.get("health") == "unhealthy" or (box.get("restarts") or 0) >= 3):
                lines.append("- " + md_cell(r["host"]) + ": контейнер " +
                             md_cell(box["name"]) + ": health=" + md_cell(box.get("health")) +
                             ", restarts=" + md_cell(box.get("restarts")))
                any_issue = True
        used = r.get("disk_root_used")
        if used and int(used.rstrip("%")) >= 85:
            lines.append("- " + md_cell(r["host"]) + ": корневой диск занят на " + used)
            any_issue = True
        for cert in r.get("certificates", []):
            try:
                expiry = dt.datetime.strptime(cert["not_after"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
                if expiry - dt.datetime.now(dt.timezone.utc) < dt.timedelta(days=30):
                    lines.append("- " + md_cell(r["host"]) + ": сертификат для " +
                                 md_cell(", ".join(cert.get("names", []))) + " истекает " +
                                 expiry.strftime("%Y-%m-%d"))
                    any_issue = True
            except (TypeError, ValueError, KeyError):
                pass
        if not r.get("backup_indicators"):
            lines.append("- " + md_cell(r["host"]) + ": задача резервного копирования не обнаружена по именам; наличие копий не установлено")
            any_issue = True
        error_count = sum(r.get("journal_errors_24h", {}).values())
        if error_count:
            lines.append("- " + md_cell(r["host"]) + ": ошибок в доступном журнале за 24 часа: " + str(error_count) + " (не более последних 300 на область)")
            any_issue = True
        for unit, categories in r.get("journal_categories_24h", {}).items():
            labels = ", ".join(label + " (" + str(number) + ")" for label, number in categories.items())
            lines.append("- " + md_cell(r["host"]) + ": журнал " + md_cell(unit) + ": " + md_cell(labels))
            any_issue = True
        for warning in r.get("warnings", []):
            lines.append("- " + md_cell(r["host"]) + ": " + md_cell(warning))
            any_issue = True
    if not any_issue:
        lines.append("- Автоматических предупреждений нет. Это не подтверждает исправность пользовательских сценариев.")
    lines += ["", "## Границы проверки", "",
              "CLI-версии не доказывают версию работающего веб-процесса. Совпадение порта не доказывает исправность приложения. Пустая графа может означать недостаток прав или нестандартную конфигурацию. Для каждого критичного сервиса отдельно проверить резервную копию, вход, права, TLS и журнал ошибок. Внутренние IP находятся только в закрытом JSON.", "",
              PROJECT_CONTACT, ""]
    return "\n".join(lines)


def plain_text(reports):
    """Present the existing structured report as ordinary text for nontechnical readers."""
    output = []
    headers = None
    for line in markdown(reports).splitlines():
        if line.startswith("# "):
            output.append(line[2:])
            continue
        if line.startswith("## "):
            output.append(line[3:].upper())
            continue
        if line.startswith("|") and line.endswith("|"):
            cells = [cell.strip().replace("\\|", "|") for cell in line[1:-1].split("|")]
            if all(re.fullmatch(r":?-+:?", cell) for cell in cells):
                continue
            if headers is None:
                headers = cells
            else:
                output.append("; ".join(label + ": " + value for label, value in zip(headers, cells)))
            continue
        if not line:
            headers = None
            output.append("")
            continue
        output.append(line.replace("`", "").replace("\\|", "|"))
    return "\n".join(output) + "\n"


def cert_name_match(name, names):
    name = name.lower()
    for pattern in names:
        pattern = pattern.lower()
        if pattern == name:
            return True
        if pattern.startswith("*.") and name.endswith(pattern[1:]):
            prefix = name[:-len(pattern[1:])]
            if prefix and "." not in prefix:
                return True
    return False


def service_cards(reports):
    """One review sheet per observed hostname. No automatic release decision."""
    lines = ["FELIX FONS — ПАСПОРТА СЕРВИСОВ", "",
             "Предварительная карта. Каждый пункт проверки имеет статус НЕ ПРОВЕРЕНО."
             " Наличие сервиса в списке не означает, что его можно включать.", ""]
    count = 0
    for r in reports:
        sites = r.get("nginx_vhosts", []) + r.get("apache_vhosts", [])
        grouped = {}
        for site in sites:
            for name in site.get("names", []):
                entry = grouped.setdefault(name, {"ports": set(), "routes": []})
                entry["ports"].update(site.get("listen", []))
                entry["routes"].extend(site.get("routes", []))
        for name, entry in sorted(grouped.items()):
            count += 1
            lines += [str(count) + ". " + name, "Узел: " + str(r.get("host", "?")),
                      "Входные порты из конфигурации: " +
                      (", ".join(map(str, sorted(entry["ports"]))) or "не определены")]
            for port in sorted(entry["ports"]):
                listening = any(item.get("port") == port for item in r.get("listeners", []))
                lines.append("Слушатель порта " + str(port) + ": " +
                             ("наблюдался" if listening else "не наблюдался; причина не установлена"))
            certs = [cert for cert in r.get("certificates", []) if cert_name_match(name, cert.get("names", []))]
            if certs:
                for cert in certs:
                    lines.append("Локальный файл сертификата: срок до " + str(cert.get("not_after") or "не определён") +
                                 "; предъявление клиенту не проверено")
            else:
                lines.append("Локальный файл сертификата для имени не сопоставлен; HTTPS требует отдельной проверки")
            if entry["routes"]:
                seen_routes = set()
                for route in entry["routes"]:
                    route_label = "Маршрут " + str(route.get("path") or "/") + ": " + resolve_target(r, route, reports)
                    if route_label not in seen_routes:
                        lines.append(route_label)
                        seen_routes.add(route_label)
            else:
                lines.append("Маршруты: статический сайт или маршруты не удалось определить")
            candidates = r.get("security_triage") or security_findings(r)
            if candidates:
                lines.append("Кандидаты узла (применимость именно к этому сайту НЕ УСТАНОВЛЕНА):")
                for issue in candidates[:20]:
                    lines.append("- " + issue["observed"] + "; проверить: " + issue["verify_before_enable"])
            lines += ["Проверки перед включением — заполнить ответственному:",
                      "Ответственный: __________   Дата: __________   Ссылки на внутренние доказательства: __________",
                      "[ ] Подтверждены владелец, назначение, тип данных и критичность сервиса.",
                      "[ ] Установлена вся цепочка от публичного входа до работающего приложения и БД.",
                      "[ ] Подтверждены версии работающих процессов, библиотек и исправления поставщика.",
                      "[ ] Проверены конфигурация, доступы администраторов, права пользователей и секреты.",
                      "[ ] Для сервисов с учётными записями проверены вход и роли.",
                      "[ ] Есть актуальная копия; пробное восстановление прошло успешно.",
                      "[ ] Проверены TLS в сетевом ответе, сетевые правила и необходимые маршруты.",
                      "[ ] Пройдены основные пользовательские сценарии и проверки ошибок.",
                      "[ ] Назначены наблюдение после запуска, ответственный и порядок отката.",
                      "Решение о включении: НЕ ПРИНЯТО", ""]
    if not count:
        lines.append("Имена сайтов на этом узле не обнаружены. Для связи с публичными адресами нужен отчёт узла входа.")
        lines.append("")
    backend_count = 0
    for r in reports:
        grouped_tunnels = {}
        for tunnel in r.get("tunnels", []):
            if tunnel.get("direction") == "R" and tunnel.get("target_port"):
                grouped_tunnels.setdefault(tunnel["target_port"], []).append(tunnel)
        for port, tunnels in sorted(grouped_tunnels.items()):
            backend_count += 1
            units = ", ".join(sorted(set(str(t.get("unit") or "?") for t in tunnels)))
            local_listener = any(item.get("port") == port for item in r.get("listeners", []))
            boxes = [box.get("name") for box in r.get("containers", [])
                     if any(bind.get("port") == port for bind in box.get("published_ports", []))]
            lines += ["ВНУТРЕННИЙ СЕРВИС " + str(backend_count) + " — локальный порт " + str(port),
                      "Узел: " + str(r.get("host", "?")),
                      "Службы обратного туннеля: " + units,
                      "Активных конфигураций туннеля: " + str(sum(bool(t.get("active")) for t in tunnels)) +
                      " из " + str(len(tunnels)),
                      "Локальный слушатель: " +
                      ("наблюдался" if local_listener else "не наблюдался; причина не установлена"),
                      "Контейнеры с таким опубликованным портом: " + (", ".join(boxes) or "не сопоставлены"),
                      "Публичный адрес: НЕ УСТАНОВЛЕН без карты входного узла.",
                      "Что проверить перед возвратом этого сервиса:",
                      "[ ] Установлены публичное имя, владелец сервиса и путь через входной узел.",
                      "[ ] Подтверждены работающий процесс, его версия, образ и исправления.",
                      "[ ] Проверены вход и роли пользователей, если они есть.",
                      "[ ] Есть испытанная резервная копия данных и понятный откат.",
                      "[ ] Пройдены проверка входа, основные сценарии, TLS и журналы после включения.",
                      "Решение о включении: НЕ ПРИНЯТО", ""]
    for r in reports:
        unmapped = r.get("containers", [])
        if unmapped:
            lines += ["Контейнеры узла " + str(r.get("host", "?")) +
                      ": привязка к конкретному сайту требует проверки"]
            for box in unmapped[:MAX_RECORDS]:
                lines.append("- " + str(box.get("name")) + " (" + str(box.get("state") or "состояние неизвестно") +
                             "), образ " + str(box.get("image_tag") or "неизвестен"))
            lines.append("")
    return "\n".join(lines) + "\n"


def secure_write(path, data):
    with open(path, "x", encoding="utf-8") as handle:
        if os.name != "nt":
            os.chmod(path, 0o600)
        handle.write(data)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    collect_parser = sub.add_parser("collect", help="read-only local inventory")
    collect_parser.add_argument("--out", type=Path, help="new output directory")
    merge_parser = sub.add_parser("merge", help="combine JSON reports offline")
    merge_parser.add_argument("reports", nargs="+", type=Path)
    merge_parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "collect":
        if platform.system() != "Linux":
            raise SystemExit("Collection supports Linux servers only")
        out = args.out or Path("campus-report-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S"))
        reports = [collect()]
    else:
        out = args.out
        reports = []
        for source in args.reports:
            item = json.loads(source.read_text(encoding="utf-8"))
            items = item if isinstance(item, list) else [item]
            for report in items:
                if not isinstance(report, dict) or report.get("schema") != 1:
                    raise SystemExit("Unsupported report schema: " + str(source))
                reports.append(report)
    out.mkdir(mode=0o700 if os.name != "nt" else 0o777, parents=False, exist_ok=False)
    secure_write(out / "inventory.private.json", json.dumps(reports[0] if len(reports) == 1 else reports,
                                                           ensure_ascii=False, indent=2) + "\n")
    secure_write(out / "summary.txt", plain_text(reports))
    secure_write(out / "service_cards.txt", service_cards(reports))
    manifest = []
    for name in ("inventory.private.json", "summary.txt", "service_cards.txt"):
        digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
        manifest.append(digest + "  " + name)
    secure_write(out / "manifest.sha256", "\n".join(manifest) + "\n")
    print("Report created: " + str(out))


if __name__ == "__main__":
    main()
