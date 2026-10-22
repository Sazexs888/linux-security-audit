#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linux Security Audit & Remediation Tool.

Скрипт выполняет только проверки и не применяет предложенные изменения.
Команды исправления являются рекомендациями: изучите их перед запуском.
Внешние Python-пакеты не используются.
"""

import argparse
import glob
import json
import logging
import os
import platform
import re
import shutil
import shlex
import stat
import subprocess
import sys
import unittest
import tempfile
from datetime import datetime, timezone

VERSION = "2.2.0"
LOG_FILE = os.path.expanduser("~/.local/share/linux_audit/audit.log")


class Color:
    """ANSI-цвета для терминального интерфейса."""
    RESET = "\033[0m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"


# Значения package_manager берутся из ID/ID_LIKE /etc/os-release.
DISTRO_MANAGERS = {
    "ubuntu": "apt", "debian": "apt", "linuxmint": "apt", "kali": "apt",
    "fedora": "dnf", "rhel": "dnf", "centos": "dnf", "rocky": "dnf",
    "almalinux": "dnf", "arch": "pacman", "manjaro": "pacman",
    "opensuse": "zypper", "opensuse-leap": "zypper", "opensuse-tumbleweed": "zypper",
    "alpine": "apk",
}
SUID_ALLOWLIST = {
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su",
    "/bin/mount", "/usr/bin/mount", "/usr/bin/chsh",
}
SUID_IGNORED_PREFIXES = ("/snap/", "/var/lib/snapd/", "/var/lib/docker/", "/var/lib/containerd/")
SUID_OWNER_COMMANDS = {
    "apt": "dpkg -S", "dnf": "rpm -qf", "zypper": "rpm -qf",
    "pacman": "pacman -Qo", "apk": "apk info --who-owns",
}
UPDATE_COMMANDS = {
    "apt": "sudo apt update && sudo apt upgrade -y",
    "dnf": "sudo dnf upgrade --refresh -y",
    "pacman": "sudo pacman -Syu",
    "zypper": "sudo zypper refresh && sudo zypper update",
    "apk": "sudo apk update && sudo apk upgrade",
}


def setup_logging(path=None):
    """Открыть приватный журнал, не меняя права уже существующих файлов."""
    path = os.path.expanduser(path or LOG_FILE)
    fd = None
    stream = None
    try:
        log_dir = os.path.dirname(path) or "."
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        # O_NOFOLLOW не позволяет незаметно открыть symlink и менять/дописывать
        # файл, на который он указывает. Для нового файла режим 0600 применяется
        # непосредственно при создании; права существующего файла не меняются.
        flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags, 0o600)
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("путь журнала не является обычным файлом")
        if stat.S_IMODE(file_stat.st_mode) & 0o077:
            raise PermissionError("у существующего журнала есть права для группы или остальных")

        stream = os.fdopen(fd, "a", encoding="utf-8")
        fd = None  # Дескриптор теперь закрывается вместе с объектом stream.
        handler = logging.StreamHandler(stream)
        logging.basicConfig(handlers=[handler], level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s", force=True)
        logging.info("Запуск Linux Security Audit Tool %s", VERSION)
        return path
    except (OSError, TypeError, ValueError) as exc:
        if fd is not None:
            os.close(fd)
        if stream is not None:
            stream.close()
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s", force=True)
        logging.warning("Не удалось безопасно открыть журнал %s (%s); используется stderr.", path, exc)
        return None


def read_os_release(path="/etc/os-release"):
    """Прочитать пары ключ-значение из os-release без выполнения файла."""
    values = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as stream:
            for line in stream:
                match = re.match(r"^([A-Z0-9_]+)=(.*)$", line.strip())
                if match:
                    values[match.group(1)] = match.group(2).strip().strip('"').strip("'")
    except OSError as exc:
        logging.warning("Не удалось прочитать %s: %s", path, exc)
    return values


def detect_distribution(os_release=None):
    """Вернуть название, ID и пакетный менеджер дистрибутива."""
    data = os_release if os_release is not None else read_os_release()
    distro_id = data.get("ID", "unknown").lower()
    candidates = [distro_id] + data.get("ID_LIKE", "").lower().split()
    manager = next((DISTRO_MANAGERS[item] for item in candidates if item in DISTRO_MANAGERS), None)
    return {
        "name": data.get("PRETTY_NAME") or data.get("NAME", "Linux (не определён)"),
        "id": distro_id,
        "package_manager": manager or "unknown",
    }


def parse_update_names(lines):
    """Извлечь имена пакетов, игнорируя служебные заголовки менеджеров."""
    ignored_prefixes = ("warning", "notice", "listing...", "last metadata", "repository")
    names = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(ignored_prefixes):
            continue
        candidate = stripped.split()[0].split("/", 1)[0].split(":", 1)[0]
        if candidate not in ("", "*", "=") and candidate not in names:
            names.append(candidate)
    return names


def evaluate_permission(path, mode):
    """Вернуть уровень режима файла; более строгая маска допустима."""
    allowed = {"/etc/passwd": 0o644, "/etc/shadow": 0o640, "/etc/sudoers": 0o440}.get(path)
    if allowed is None or not (mode & ~allowed):
        return "OK"
    sensitive = path in ("/etc/shadow", "/etc/sudoers")
    exposed = bool(mode & 0o077)
    return "CRITICAL" if sensitive and exposed else "WARNING"


def classify_suid_paths(paths, allowlist=None):
    """Разделить SUID-пути на подозрительные и ожидаемые snap/container пути."""
    allowed = SUID_ALLOWLIST if allowlist is None else allowlist
    unusual, isolated = [], []
    for path in paths:
        if path in allowed:
            continue
        if path.startswith(SUID_IGNORED_PREFIXES):
            isolated.append(path)
        else:
            unusual.append(path)
    return unusual, isolated


def update_result_status(manager, returncode, package_names):
    """Нормализовать разные коды возврата менеджеров обновлений."""
    accepted = {"apt": (0,), "dnf": (0, 100), "pacman": (0, 1),
                "zypper": (0,), "apk": (0,)}.get(manager, (0,))
    if returncode not in accepted:
        return "ERROR"
    return "UPDATES" if package_names else "OK"


def command_result(args, timeout=15):
    """Выполнить диагностическую команду без shell; вернуть None при ошибке."""
    try:
        return subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        logging.warning("Команда %r не выполнена: %s", args, exc)
        return None


def parse_sshd_config_tree(main_path="/etc/ssh/sshd_config"):
    """Прочитать глобальные параметры sshd_config и Include без Match-значений."""
    config = {}
    active_paths = set()
    has_match = False

    def _read_file(filepath, conditional=False):
        nonlocal has_match
        if not os.path.isfile(filepath):
            return conditional
        real_path = os.path.realpath(filepath)
        if real_path in active_paths:
            logging.warning("Циклический Include в конфигурации SSH: %s", filepath)
            return conditional
        active_paths.add(real_path)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("#", 1)[0].split(None, 1)
                    if len(parts) < 2:
                        continue
                    key = parts[0].lower()
                    val = parts[1].strip()
                    if key == "match":
                        has_match = True
                        conditional = True
                        continue
                    if key == "include":
                        for include_pattern in shlex.split(val):
                            pattern = (include_pattern if include_pattern.startswith("/") else
                                       os.path.join(os.path.dirname(filepath), include_pattern))
                            for inc_path in sorted(glob.glob(pattern)):
                                conditional = _read_file(inc_path, conditional)
                    elif not conditional:
                        # В OpenSSH первое указанное значение имеет наивысший приоритет
                        if key not in config:
                            config[key] = val.lower()
        except OSError as exc:
            logging.warning("Не удалось прочитать SSH конфиг %s: %s", filepath, exc)
        finally:
            active_paths.discard(real_path)
        return conditional

    _read_file(main_path)
    if has_match:
        config["_has_match"] = "yes"
    return config


class LinuxSecurityAudit:
    """Аудитор Linux: собирает findings, не изменяя настройки системы."""

    def __init__(self):
        self.results = []
        self.system = {}
        self.distro = detect_distribution()
        self.is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    def finding(self, check_id, category, level, title, reason, remediation, details=None):
        """Добавить структурированную находку с объяснением и советом."""
        item = {
            "id": check_id, "category": category, "level": level,
            "title": title, "description": title, "reason": reason,
            "remediation": remediation, "details": details or {},
        }
        self.results.append(item)
        logging.info("%s %s: %s", level, check_id, title)

    def check_system(self):
        """Собрать сведения об ОС и ядре."""
        result = command_result(["uname", "-r"])
        self.system = {
            "distribution": self.distro["name"], "distribution_id": self.distro["id"],
            "package_manager": self.distro["package_manager"],
            "kernel": result.stdout.strip() if result and result.returncode == 0 else platform.release(),
            "architecture": platform.machine(),
            "is_root": self.is_root,
            "audit_time_utc": datetime.now(timezone.utc).isoformat(),
        }
        self.finding("SYS-001", "Система", "INFO", "Определена ОС и версия ядра.",
                     "Эти сведения помогают выбрать применимые рекомендации.",
                     "Обновляйте систему штатным менеджером пакетов.", self.system)

    def check_permissions(self):
        """Проверить режимы доступа к ключевым системным файлам."""
        policies = {
            "/etc/passwd": (0o644, "Содержит сведения об учетных записях."),
            "/etc/shadow": (0o640, "Содержит хеши паролей пользователей."),
            "/etc/sudoers": (0o440, "Определяет, кто может получать привилегии."),
        }
        for path, (allowed, reason) in policies.items():
            try:
                mode = stat.S_IMODE(os.stat(path, follow_symlinks=True).st_mode)
            except OSError as exc:
                lvl = "WARNING" if not self.is_root else "CRITICAL"
                self.finding("PERM-001", "Права доступа", lvl, "Не удалось проверить {}.".format(path),
                             "Без метаданных файла нельзя подтвердить его защиту.",
                             "Проверьте наличие и доступность файла: sudo stat {}".format(path), {"path": path, "error": str(exc)})
                continue
            level = evaluate_permission(path, mode)
            if level != "OK":
                self.finding("PERM-002", "Права доступа", level,
                             "Слишком широкие права у {} ({:04o}).".format(path, mode), reason,
                             "sudo chmod {:04o} {}".format(allowed, path),
                             {"path": path, "mode": "{:04o}".format(mode)})
            else:
                self.finding("PERM-OK", "Права доступа", "OK", "Права {} допустимы.".format(path),
                             "Текущая маска не шире принятого базового значения.",
                             "Исправление не требуется.", {"path": path, "mode": "{:04o}".format(mode)})

    def check_accounts(self, passwd_path="/etc/passwd", shadow_path="/etc/shadow"):
        """Найти дополнительные UID 0 и пустые поля паролей."""
        try:
            with open(passwd_path, encoding="utf-8", errors="replace") as stream:
                users = [line.rstrip("\n").split(":") for line in stream if line.count(":") >= 6]
        except OSError as exc:
            self.finding("USER-001", "Пользователи", "WARNING", "Не удалось прочитать /etc/passwd.",
                         "Проверка привилегированных учётных записей не завершена.",
                         "Проверьте файл: sudo getent passwd", {"error": str(exc)})
            return
        extra = [u[0] for u in users if u[2] == "0" and u[0] != "root"]
        if extra:
            self.finding("USER-002", "Пользователи", "CRITICAL", "Найдены дополнительные пользователи с UID 0.",
                         "UID 0 предоставляет полные привилегии root.",
                         "Проверьте аккаунты и удалите или переназначьте UID: sudo usermod -u <новый_UID> <пользователь>", {"users": extra})
        else:
            self.finding("USER-OK", "Пользователи", "OK", "Дополнительных UID 0 нет.",
                         "Только аккаунт root имеет UID 0.", "Исправление не требуется.")
        try:
            with open(shadow_path, encoding="utf-8", errors="replace") as stream:
                empty = []
                for line in stream:
                    parts = line.rstrip("\n").split(":")
                    if len(parts) > 1 and parts[1] == "":
                        empty.append(parts[0])
        except PermissionError:
            self.finding("PASS-001", "Пароли", "WARNING", "Недостаточно прав для чтения /etc/shadow.",
                         "Нельзя проверить, есть ли аккаунты с пустым полем пароля без прав root.",
                         "Запустите аудит с правами суперпользователя: sudo ./audit_pro.py")
            return
        except OSError as exc:
            self.finding("PASS-001", "Пароли", "WARNING", "Не удалось прочитать /etc/shadow.",
                         "Проверка пустых паролей не завершена.", "Проверьте доступность файла /etc/shadow.", {"error": str(exc)})
            return
        if empty:
            self.finding("PASS-002", "Пароли", "CRITICAL", "Обнаружено пустое поле пароля.",
                         "Поле пароля пустое; возможность входа зависит от PAM и настроек службы.",
                         "Задайте пароль: sudo passwd <пользователь> (либо заблокируйте аккаунт: sudo passwd -l <пользователь>).", {"users": empty})
        else:
            self.finding("PASS-OK", "Пароли", "OK", "Пустых полей пароля не обнаружено.",
                         "Проверенные записи shadow содержат значение пароля или блокировки.", "Исправление не требуется.")

    def check_network(self):
        """Проверить слушающие порты через ss и отметить типовые опасные службы."""
        if not shutil.which("ss"):
            self.finding("NET-001", "Сеть", "WARNING", "Утилита ss не найдена.",
                         "Список слушающих портов получить не удалось.",
                         "Установите пакет iproute2 средствами вашего дистрибутива.")
            return
        proc = command_result(["ss", "-tuln"])
        if not proc or proc.returncode != 0:
            self.finding("NET-001", "Сеть", "WARNING", "Не удалось выполнить ss -tuln.",
                         "Слушающие порты остались непроверенными.", "Запустите ss -tuln вручную.")
            return
        risky = {21: ("FTP", "Отключите FTP-службу, если она не нужна: sudo systemctl disable --now vsftpd"),
                 23: ("Telnet", "Отключите Telnet: sudo systemctl disable --now telnet.socket"),
                 3306: ("MySQL", "Ограничьте MySQL локальным интерфейсом в конфигурации и перезапустите службу.")}
        found = []
        for line in proc.stdout.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 5:
                continue
            address = fields[4]
            match = re.search(r":(\d+)$", address)
            if not match:
                continue
            port = int(match.group(1))
            wildcard = address.startswith(("0.0.0.0:", "*:", "[::]:")) or address == "::"
            found.append({"address": address, "port": port})
            if port in risky:
                service, remedy = risky[port]
                level = "CRITICAL" if wildcard else "WARNING"
                exposure = "на всех интерфейсах" if wildcard else "на конкретном адресе"
                reason = "{} на порту {} доступен {}. Незащищённая служба повышает риск удалённого доступа.".format(service, port, exposure)
                self.finding("NET-{:04d}".format(port), "Сеть", level,
                             "Порт {} ({}) слушает {}.".format(port, service, address), reason, remedy,
                             {"port": port, "address": address, "service": service})
        if not any(item["port"] in risky for item in found):
            self.finding("NET-OK", "Сеть", "OK", "Типовые опасные порты не найдены.",
                         "Порты 21, 23 и 3306 не обнаружены в выводе ss.", "Исправление не требуется.")
        self.finding("NET-INFO", "Сеть", "INFO", "Получен список слушающих сокетов.",
                     "Локальная привязка не гарантирует доступность из интернета; firewall отдельно не проверялся.",
                     "При необходимости проверьте firewall и сетевые ACL.", {"listeners": found})

    def check_temp(self):
        """Просканировать верхний уровень временных каталогов на исполняемые/SUID файлы."""
        for directory in ("/tmp", "/var/tmp"):
            suspicious = []
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        try:
                            info = entry.stat(follow_symlinks=False)
                            if not stat.S_ISREG(info.st_mode):
                                continue
                            reasons = []
                            if entry.name.lower().endswith((".sh", ".elf", ".py")):
                                reasons.append("подозрительное расширение")
                            if info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                                reasons.append("исполняемый файл")
                            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                                reasons.append("SUID/SGID")
                            if reasons:
                                suspicious.append({"path": entry.path, "reasons": reasons})
                        except OSError:
                            continue
            except OSError as exc:
                self.finding("TMP-001", "Временные файлы", "WARNING", "Не удалось просканировать {}.".format(directory),
                             "Часть временных файлов не прошла проверку.", "Проверьте каталог с правами root.", {"error": str(exc)})
                continue
            if suspicious:
                self.finding("TMP-002", "Временные файлы", "WARNING", "Есть файлы для ручной проверки в {}.".format(directory),
                             "Исполняемые и SUID/SGID файлы во временных каталогах могут быть легитимны, но требуют проверки владельца и происхождения.",
                             "Проверьте файл: ls -l <путь>; удаляйте только после подтверждения, что он не нужен.", {"files": suspicious})
            else:
                self.finding("TMP-OK", "Временные файлы", "OK", "Подозрительные файлы в {} не найдены.".format(directory),
                             "Верхний уровень каталога проверен.", "Исправление не требуется.")

    def check_suid_files(self):
        """Найти SUID-файлы с флагом -xdev (строго в пределах одной локальной ФС)."""
        allowlist = SUID_ALLOWLIST
        # Флаг -xdev гарантирует отсутствие перехода на сетевые хранилища (NFS/CIFS) или другие устройства.
        try:
            proc = subprocess.run(
                ["find", "/", "-xdev", "-perm", "-4000", "-type", "f"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, check=False, timeout=90,
            )
        except FileNotFoundError:
            self.finding("SUID-001", "SUID", "WARNING", "Команда find не найдена.",
                         "Сканирование SUID-файлов не выполнено.",
                         "Установите findutils средствами вашего дистрибутива.")
            return
        except subprocess.TimeoutExpired:
            self.finding("SUID-001", "SUID", "WARNING", "Сканирование SUID-файлов превысило лимит времени.",
                         "Поиск SUID-бинарников занял слишком много времени.",
                         "Повторите аудит в период низкой нагрузки на диск.")
            return
        except OSError as exc:
            self.finding("SUID-001", "SUID", "WARNING", "Не удалось запустить поиск SUID-файлов.",
                         "Проверка не завершена.", "Убедитесь, что доступна команда find.", {"error": str(exc)})
            return
        found = sorted(set(path.strip() for path in proc.stdout.splitlines() if path.strip()))
        unusual, isolated = classify_suid_paths(found, allowlist)
        ownership = SUID_OWNER_COMMANDS.get(self.distro["package_manager"], "file")
        if unusual:
            details = [{"path": path, "owner_check": "{} {}".format(ownership, shlex.quote(path))}
                       for path in unusual]
            self.finding("SUID-002", "SUID", "WARNING",
                         "Найдены SUID-файлы вне базового списка ({}/{}).".format(len(unusual), len(found)),
                         "SUID-программа запускается с эффективными правами владельца. Дополнительный файл может быть легитимным, но его владелец и назначение требуют проверки.",
                         "Проверьте каждый путь командами ls -l <путь> и {} <путь>; удаляйте SUID-бит только после проверки.".format(ownership),
                         {"files": details, "scanned_count": len(found), "allowlist": sorted(allowlist)})
        else:
            self.finding("SUID-OK", "SUID", "OK", "Необычных SUID-файлов вне исключений не найдено.",
                         "Файлы совпали с базовым allowlist или находятся в изолированных путях.",
                         "Исправление не требуется.", {"scanned_count": len(found), "allowlist": sorted(allowlist)})
        if isolated:
            self.finding("SUID-003", "SUID", "INFO",
                         "SUID-файлы в путях snap/контейнеров: {}.".format(len(isolated)),
                         "Образы и изолированные пакетные файловые системы могут содержать штатные SUID-бинарники; эта классификация не подтверждает их безопасность.",
                         "Действий не требуется, если эти образы и пакеты доверенные.",
                         {"count": len(isolated), "files": isolated[:10]})

    def check_updates(self):
        """Получить список доступных обновлений без их установки."""
        manager = self.distro["package_manager"]
        command = {"apt": ["apt", "list", "--upgradable"],
                   "dnf": ["dnf", "-q", "check-update"],
                   "pacman": ["pacman", "-Qu"],
                   "zypper": ["zypper", "--non-interactive", "list-updates"],
                   "apk": ["apk", "version", "-l", "<"]}.get(manager)
        if not command or not shutil.which(command[0]):
            remedy = UPDATE_COMMANDS.get(manager, "Определите пакетный менеджер и выполните штатную проверку обновлений.")
            self.finding("UPD-001", "Обновления", "WARNING", "Невозможно проверить обновления.",
                         "Не найден поддерживаемый менеджер пакетов или команда.", remedy,
                         {"package_manager": manager})
            return
        proc = command_result(command, timeout=30)
        if proc is None:
            lines = []
        else:
            lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        names = parse_update_names(lines)
        status = update_result_status(manager, proc.returncode, names) if proc is not None else "ERROR"
        if status == "ERROR":
            self.finding("UPD-001", "Обновления", "WARNING", "Менеджер пакетов не смог проверить обновления.",
                         "Проверка завершилась ошибкой; возможно, нужны права root или отсутствует интернет-соединение.",
                         UPDATE_COMMANDS.get(manager, "Проверьте настройки репозиториев."),
                         {"error": proc.stderr.strip() if proc else "команда не запущена",
                          "returncode": proc.returncode if proc else None})
        elif status == "UPDATES":
            self.finding("UPD-002", "Обновления", "WARNING", "Доступны обновления пакетов ({}).".format(len(names)),
                         "Неустановленные обновления могут содержать исправления известных уязвимостей.",
                         UPDATE_COMMANDS.get(manager, "Обновите систему штатным менеджером пакетов."),
                         {"packages": names, "count": len(names), "package_manager": manager})
        else:
            self.finding("UPD-OK", "Обновления", "OK", "Список ожидающих обновления пакетов пуст.",
                         "Менеджер пакетов не сообщил об обновлениях.", "Исправление не требуется.")

    def check_ssh(self, path="/etc/ssh/sshd_config"):
        """Проверить активные директивы SSH с рекурсивной обработкой Include."""
        if not os.path.exists(path):
            self.finding("SSH-000", "SSH", "INFO", "OpenSSH Server не установлен — проверка пропущена.",
                         "Файл sshd_config отсутствует.",
                         "Устанавливайте openssh-server только если нужен удалённый доступ.", {"path": path})
            return

        config = parse_sshd_config_tree(path)
        has_match = config.pop("_has_match", "no") == "yes"
        if not config and not has_match:
            self.finding("SSH-001", "SSH", "WARNING", "Не удалось прочитать параметры sshd_config.",
                         "Конфигурационный файл пуст или недоступен для чтения.",
                         "Проверьте права доступа к каталогу /etc/ssh/.", {"path": path})
            return

        root = config.get("permitrootlogin", "prohibit-password")
        if root == "yes":
            self.finding("SSH-002", "SSH", "CRITICAL", "SSH разрешает прямой вход root.",
                         "Компрометация root-пароля сразу даёт удалённые административные права.",
                         "Установите PermitRootLogin no в sshd_config (или в sshd_config.d/), проверьте конфиг и перезапустите ssh.",
                         {"actual_value": root})
        else:
            self.finding("SSH-OK-ROOT", "SSH", "OK", "Прямой вход root под паролем заблокирован.",
                         "Значение PermitRootLogin не равно 'yes'.", "Исправление не требуется.", {"value": root})

        password = config.get("passwordauthentication", "yes")
        if password == "yes":
            self.finding("SSH-003", "SSH", "WARNING", "SSH разрешает парольную аутентификацию.",
                         "Пароли подвержены перебору и перехвату; вход по SSH-ключам безопаснее.",
                         "Настройте вход по SSH-ключам и задайте PasswordAuthentication no в sshd_config.",
                         {"actual_value": password})
        else:
            self.finding("SSH-OK-PASS", "SSH", "OK", "Парольный вход по SSH отключен.",
                         "Используется аутентификация по публичным ключам.", "Исправление не требуется.", {"value": password})

        if has_match:
            self.finding("SSH-004", "SSH", "WARNING",
                         "В SSH-конфигурации есть условные блоки Match.",
                         "Их настройки зависят от пользователя и адреса подключения и не сводятся к одному глобальному значению.",
                         "Проверьте эффективные параметры для нужного подключения: sudo sshd -T -C user=ИМЯ,host=ИМЯ_ХОСТА,addr=IP",
                         {"conditional_settings_checked": False})

    def run(self):
        """Запустить весь набор проверок и вернуть сериализуемый отчёт."""
        for check in (self.check_system, self.check_permissions, self.check_accounts,
                      self.check_network, self.check_temp, self.check_suid_files,
                      self.check_updates, self.check_ssh):
            try:
                check()
            except Exception:
                logging.exception("Ошибка в проверке %s", check.__name__)
                self.finding("ERR-001", "Внутренняя ошибка", "WARNING",
                             "Проверка {} завершилась с ошибкой.".format(check.__name__),
                             "Часть аудита не дала результата.", "Посмотрите журнал и повторите запуск.")
        summary = {level.lower(): sum(item["level"] == level for item in self.results)
                   for level in ("CRITICAL", "WARNING", "INFO", "OK")}
        return {"tool": "Linux Security Audit Tool", "version": VERSION,
                "system": self.system, "results": self.results,
                "summary": summary, "total_checks": len(self.results)}


SECTIONS = ["Система", "Права доступа", "Пользователи", "Пароли", "Сеть",
            "Временные файлы", "SUID", "Обновления", "SSH", "Внутренняя ошибка"]
LEVEL_COLORS = {"CRITICAL": Color.RED, "WARNING": Color.YELLOW,
                "OK": Color.GREEN, "INFO": Color.CYAN}


def display_table(headers, rows):
    """Показать таблицу без внешних библиотек."""
    widths = [len(str(header)) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = min(max(widths[index], len(str(value))), 58)
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    print(border)
    print("|" + "|".join(" {:<{}} ".format(header, width) for header, width in zip(headers, widths)) + "|")
    print(border)
    for row in rows:
        cells = []
        for value, width in zip(row, widths):
            value = str(value)
            if len(value) > width:
                value = value[:max(0, width - 1)] + "…"
            cells.append(" {:<{}} ".format(value, width))
        print("|" + "|".join(cells) + "|")
    print(border)


def print_banner(color=True):
    """Показать заголовок утилиты и раннее предупреждение о привилегиях."""
    blue = Color.CYAN if color else ""
    yellow = Color.YELLOW if color else ""
    reset = Color.RESET if color else ""
    print(blue + r"""
  _      _                    ____                  _ _ _
 | |    (_)_ __  _   ___  __ / ___|  ___  ___ _   _| |_ |_
 | |    | | '_ \| | | \ \/ /| |  _ / _ \/ __| | | | | __|
 | |___ | | | | | |_| |>  < | |_| |  __/ (__| |_| | | |_
 |_____|_|_| |_|\__,_/_/\_\\____|\___|\___|\__,_|_|\__|
             SECURITY AUDIT & REMEDIATION TOOL v""" + VERSION + "\n" + reset)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("{}[!] Запущено без root: часть проверок (/etc/shadow, закрытые сокеты) будут ограничены.{}\n".format(yellow, reset))


def print_report(report, color=True):
    """Вывести отчёт блоками: сводная таблица и подробные рекомендации."""
    print_banner(color)
    system = report["system"]
    print("{} | ядро {} | менеджер пакетов: {}".format(
        system.get("distribution", "Linux"), system.get("kernel", "?"), system.get("package_manager", "?")))
    for section in SECTIONS:
        items = [item for item in report["results"] if item["category"] == section]
        if not items:
            continue
        header_color = Color.BLUE if color else ""
        reset = Color.RESET if color else ""
        print("\n{}[ {} ]{}".format(header_color, section.upper(), reset))
        rows = []
        for item in items:
            rows.append((item["id"], item["level"], item["title"]))
        display_table(("ID", "Уровень", "Описание"), rows)
        for item in items:
            if item["level"] in ("OK", "INFO"):
                continue
            status_color = LEVEL_COLORS.get(item["level"], "") if color else ""
            print("{}[{}] {}{}".format(status_color, item["level"], item["title"], Color.RESET if color else ""))
            print("  Причина: {}".format(item["reason"]))
            print("  Как исправить: {}".format(item["remediation"]))
            details = item.get("details", {})
            packages = details.get("packages", [])
            if packages:
                for package in packages[:5]:
                    print("    • {}".format(package))
                if len(packages) > 5:
                    print("    • и еще {} пакетов".format(len(packages) - 5))
            files = details.get("files", [])
            if files:
                for entry in files[:10]:
                    if isinstance(entry, dict):
                        print("    • {}{}".format(entry.get("path", "?"),
                              " — " + entry["owner_check"] if entry.get("owner_check") else ""))
                    else:
                        print("    • {}".format(entry))
                if len(files) > 10:
                    print("    • и еще {} файлов".format(len(files) - 10))
            users = details.get("users", [])
            if users:
                print("    Аккаунты: {}".format(", ".join(map(str, users))))
    summary = report["summary"]
    labels = ["Всего проверок: {}".format(report["total_checks"]),
              "Критических: {}".format(summary["critical"]),
              "Предупреждений: {}".format(summary["warning"]),
              "Информационных: {}".format(summary["info"]),
              "ОК: {}".format(summary["ok"])]
    width = max(map(len, labels)) + 4
    blue = Color.BLUE if color else ""
    reset = Color.RESET if color else ""
    print("\n{}╔{}╗{}".format(blue, "═" * width, reset))
    print("{}║{:^{}}║{}".format(blue, "ИТОГОВЫЙ ОТЧЕТ", width, reset))
    print("{}╠{}╣{}".format(blue, "═" * width, reset))
    for label in labels:
        print("{}║  {:<{}}║{}".format(blue, label, width - 2, reset))
    print("{}╚{}╝{}".format(blue, "═" * width, reset))


def interactive_remediation(report):
    """Показать команды исправления по запросу; ничего не исполнять автоматически."""
    actionable = [item for item in report["results"] if item["level"] in ("CRITICAL", "WARNING")]
    if not actionable or not sys.stdin.isatty():
        return
    try:
        answer = input("Хотите просмотреть рекомендации по исправлению проблем? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if answer not in ("y", "yes", "д", "да"):
        return
    print("\nКоманды не запускались. Проверьте их применимость перед ручным выполнением:\n")
    for item in actionable:
        print("{} [{}] {}\n  {}".format(item["id"], item["level"], item["title"], item["remediation"]))


class AuditSelfTests(unittest.TestCase):
    """Небольшие автономные проверки вспомогательной логики."""

    def test_distro_mapping(self):
        self.assertEqual(detect_distribution({"ID": "ubuntu"})["package_manager"], "apt")
        self.assertEqual(detect_distribution({"ID": "arch"})["package_manager"], "pacman")
        self.assertEqual(detect_distribution({"ID": "alpine"})["package_manager"], "apk")

    def test_update_parser_skips_warnings_and_deduplicates(self):
        names = parse_update_names([
            "WARNING: apt does not have a stable CLI interface.",
            "Listing... Done", "curl/jammy 7.81 amd64 [upgradable from: 7.80]",
            "curl/jammy 7.81 amd64 [upgradable from: 7.80]",
            "linux-image-6.8.0-45:amd64/jammy 6.8.0 amd64", "name/stable 1 all",
            "openssl/jammy 3.0 all",
        ])
        self.assertEqual(names, ["curl", "linux-image-6.8.0-45", "name", "openssl"])

    def test_suid_allowlist_is_defined(self):
        self.assertIn("/usr/bin/passwd", SUID_ALLOWLIST)
        self.assertEqual(SUID_OWNER_COMMANDS["apt"], "dpkg -S")
        self.assertEqual(SUID_OWNER_COMMANDS["dnf"], "rpm -qf")

    def test_restrictive_permissions_are_accepted(self):
        self.assertEqual(evaluate_permission("/etc/passwd", 0o600), "OK")
        self.assertEqual(evaluate_permission("/etc/shadow", 0o600), "OK")
        self.assertEqual(evaluate_permission("/etc/passwd", 0o664), "WARNING")
        self.assertEqual(evaluate_permission("/etc/shadow", 0o644), "CRITICAL")

    def test_suid_snap_paths_are_classified_as_info(self):
        unusual, isolated = classify_suid_paths([
            "/snap/core22/usr/bin/passwd", "/var/lib/docker/overlay2/layer/usr/bin/su",
            "/opt/strange-suid", "/usr/bin/passwd",
        ])
        self.assertEqual(unusual, ["/opt/strange-suid"])
        self.assertEqual(len(isolated), 2)

    def test_missing_ssh_config_is_info(self):
        audit = LinuxSecurityAudit()
        audit.check_ssh(path="/definitely/missing/sshd_config")
        self.assertEqual(len(audit.results), 1)
        self.assertEqual(audit.results[0]["id"], "SSH-000")
        self.assertEqual(audit.results[0]["level"], "INFO")

    def test_ssh_include_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            main_conf = os.path.join(directory, "sshd_config")
            inc_dir = os.path.join(directory, "sshd_config.d")
            os.makedirs(inc_dir, exist_ok=True)
            custom_conf = os.path.join(inc_dir, "50-cloud.conf")

            with open(main_conf, "w", encoding="utf-8") as stream:
                stream.write("Include {}/*.conf\nPasswordAuthentication yes\n".format(inc_dir))
            with open(custom_conf, "w", encoding="utf-8") as stream:
                stream.write("PermitRootLogin no\nPasswordAuthentication no\n")

            cfg = parse_sshd_config_tree(main_conf)
            self.assertEqual(cfg.get("permitrootlogin"), "no")
            # Значение из Include парсится первым, поэтому PasswordAuthentication равен 'no'
            self.assertEqual(cfg.get("passwordauthentication"), "no")

    def test_empty_shadow_password_is_critical(self):
        with tempfile.TemporaryDirectory() as directory:
            passwd_path = os.path.join(directory, "passwd")
            shadow_path = os.path.join(directory, "shadow")
            with open(passwd_path, "w", encoding="utf-8") as stream:
                stream.write("root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n")
            with open(shadow_path, "w", encoding="utf-8") as stream:
                stream.write("root:!:1:0:99999:7:::\nalice::1:0:99999:7:::\n")
            audit = LinuxSecurityAudit()
            audit.check_accounts(passwd_path, shadow_path)
            result = next(item for item in audit.results if item["id"] == "PASS-002")
            self.assertEqual(result["level"], "CRITICAL")
            self.assertEqual(result["details"]["users"], ["alice"])

    def test_pacman_no_updates_is_success(self):
        self.assertEqual(update_result_status("pacman", 1, []), "OK")
        self.assertEqual(update_result_status("pacman", 0, ["bash"]), "UPDATES")
        self.assertEqual(update_result_status("apt", 2, []), "ERROR")
        self.assertEqual(update_result_status("dnf", 100, ["bash"]), "UPDATES")

    def test_update_commands_exist(self):
        for manager in ("apt", "dnf", "pacman", "zypper", "apk"):
            self.assertTrue(UPDATE_COMMANDS[manager].startswith("sudo "))

    def test_finding_report_shape(self):
        audit = LinuxSecurityAudit()
        audit.finding("TEST-001", "Тест", "INFO", "Проверка", "Причина", "Рекомендация")
        item = audit.results[0]
        self.assertEqual(item["id"], "TEST-001")
        self.assertIn("remediation", item)
        self.assertEqual(item["reason"], "Причина")


def run_self_tests():
    """Запустить unittest; сетевые и системные изменения тестами не выполняются."""
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AuditSelfTests)
    return unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful()


def interactive_app():
    """Главный цикл приложения для обычного интерактивного терминала."""
    while True:
        print_banner(color=sys.stdout.isatty())
        header = Color.BLUE if sys.stdout.isatty() else ""
        reset = Color.RESET if sys.stdout.isatty() else ""
        print("{}╔════════════════════════════════════════════════════╗{}".format(header, reset))
        print("{}║                 ГЛАВНОЕ МЕНЮ                       ║{}".format(header, reset))
        print("{}╠════════════════════════════════════════════════════╣{}".format(header, reset))
        print("{}║  1. Запустить полный аудит                         ║{}".format(header, reset))
        print("{}║  2. Запустить самопроверку                          ║{}".format(header, reset))
        print("{}║  c. Очистить экран                                  ║{}".format(header, reset))
        print("{}║  3. Выход                                           ║{}".format(header, reset))
        print("{}╚════════════════════════════════════════════════════╝{}".format(header, reset))
        try:
            choice = input("Выберите действие [1-3]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nРабота завершена.")
            return 0
        if choice in ("c", "clear", "очистить"):
            if sys.stdout.isatty():
                print("\033[2J\033[H", end="", flush=True)
            continue
        if choice in ("3", "q", "quit", "выход"):
            print("Работа завершена.")
            return 0
        if choice == "2":
            success = run_self_tests()
            print("Самопроверка: {}.".format("успешно" if success else "есть ошибки"))
        elif choice == "1":
            try:
                report = LinuxSecurityAudit().run()
                print_report(report, color=sys.stdout.isatty())
                interactive_remediation(report)
                logging.info("Аудит завершён: %s", json.dumps(report["summary"], ensure_ascii=False))
            except KeyboardInterrupt:
                print("\nАудит прерван пользователем.")
                logging.warning("Аудит прерван пользователем")
        else:
            print("Введите 1, 2 или 3.")
        try:
            input("\nНажмите Enter, чтобы вернуться в меню...")
        except (EOFError, KeyboardInterrupt):
            print("\nРабота завершена.")
            return 0


def main(argv=None):
    """Точка входа для CLI, JSON-режима и интерактивного приложения."""
    parser = argparse.ArgumentParser(description="Linux Security Audit & Remediation Tool (только аудит)")
    parser.add_argument("--json", action="store_true", help="Вывести отчёт в JSON.")
    parser.add_argument("--self-test", action="store_true", help="Запустить встроенные unittest и выйти.")
    parser.add_argument("--log-file", default=LOG_FILE, help="Путь к файлу журнала.")
    parser.add_argument("--menu", action="store_true", help="Открыть интерактивное меню.")
    parser.add_argument("--once", action="store_true", help="Выполнить аудит один раз без меню.")
    args = parser.parse_args(argv)
    setup_logging(args.log_file)
    if args.self_test:
        return 0 if run_self_tests() else 1
    if args.menu or (not args.once and not args.json and sys.stdin.isatty()):
        return interactive_app()
    report = LinuxSecurityAudit().run()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report, color=sys.stdout.isatty())
        interactive_remediation(report)
    logging.info("Аудит завершён: %s", json.dumps(report["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
