#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linux Security Audit & Remediation Tool.

Скрипт выполняет только проверки и не применяет предложенные изменения.
Команды исправления являются рекомендациями: изучите их перед запуском.
Внешние Python-пакеты не используются.
"""

import argparse
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
from datetime import datetime, timezone

VERSION = "2.0.0"
LOG_FILE = "linux_security_audit.log"


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


def setup_logging(path=LOG_FILE):
    """Настроить журналирование в файл; ошибка лог-файла не прерывает аудит."""
    try:
        logging.basicConfig(filename=path, level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s",
                            encoding="utf-8", force=True)
        logging.info("Запуск Linux Security Audit Tool %s", VERSION)
        return path
    except (OSError, TypeError):
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s", force=True)
        logging.warning("Не удалось открыть %s; используется stderr.", path)
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
    ignored_prefixes = ("warning", "notice", "listing...", "name", "last metadata", "repository")
    names = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(ignored_prefixes):
            continue
        candidate = stripped.split()[0].split("/", 1)[0]
        if candidate not in ("", "*", "=") and candidate not in names:
            names.append(candidate)
    return names


def command_result(args, timeout=15):
    """Выполнить диагностическую команду без shell; вернуть None при ошибке."""
    try:
        return subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        logging.warning("Команда %r не выполнена: %s", args, exc)
        return None


class LinuxSecurityAudit:
    """Аудитор Linux: собирает findings, не изменяя настройки системы."""

    def __init__(self):
        self.results = []
        self.system = {}
        self.distro = detect_distribution()

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
                self.finding("PERM-001", "Права доступа", "WARNING", "Не удалось проверить {}.".format(path),
                             "Без метаданных файла нельзя подтвердить его защиту.",
                             "Проверьте наличие и доступность файла: sudo stat {}".format(path), {"path": path, "error": str(exc)})
                continue
            if mode & ~allowed:
                critical = path in ("/etc/shadow", "/etc/sudoers")
                self.finding("PERM-002", "Права доступа", "CRITICAL" if critical else "WARNING",
                             "Слишком широкие права у {} ({:04o}).".format(path, mode), reason,
                             "sudo chmod {:04o} {}".format(allowed, path),
                             {"path": path, "mode": "{:04o}".format(mode)})
            else:
                self.finding("PERM-OK", "Права доступа", "OK", "Права {} допустимы.".format(path),
                             "Текущая маска не шире принятого базового значения.",
                             "Исправление не требуется.", {"path": path, "mode": "{:04o}".format(mode)})

    def check_accounts(self):
        """Найти дополнительные UID 0 и пустые поля паролей."""
        try:
            with open("/etc/passwd", encoding="utf-8", errors="replace") as stream:
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
            with open("/etc/shadow", encoding="utf-8", errors="replace") as stream:
                empty = [parts[0] for line in stream if len(parts := line.rstrip("\n").split(":")) > 1 and parts[1] == ""]
        except PermissionError:
            self.finding("PASS-001", "Пароли", "WARNING", "Недостаточно прав для чтения /etc/shadow.",
                         "Нельзя проверить, есть ли аккаунты с пустым полем пароля.",
                         "Повторите аудит с правами root.")
            return
        except OSError as exc:
            self.finding("PASS-001", "Пароли", "WARNING", "Не удалось прочитать /etc/shadow.",
                         "Проверка пустых паролей не завершена.", "Проверьте доступность файла /etc/shadow.", {"error": str(exc)})
            return
        if empty:
            self.finding("PASS-002", "Пароли", "CRITICAL", "Обнаружено пустое поле пароля.",
                         "Такой аккаунт может допускать вход без пароля, если это разрешают остальные настройки.",
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
        """Найти SUID-файлы и отметить записи вне небольшого базового allowlist."""
        allowlist = SUID_ALLOWLIST
        # find только читает метаданные. Ограничение по времени защищает от зависания
        # на сетевых или неисправных файловых системах; stderr подавлен из-за
        # ожидаемых ошибок доступа при запуске без root.
        try:
            proc = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, check=False, timeout=120,
            )
        except FileNotFoundError:
            self.finding("SUID-001", "SUID", "WARNING", "Команда find не найдена.",
                         "Сканирование SUID-файлов не выполнено.",
                         "Установите findutils средствами вашего дистрибутива.")
            return
        except subprocess.TimeoutExpired:
            self.finding("SUID-001", "SUID", "WARNING", "Сканирование SUID-файлов превысило лимит времени.",
                         "Полный проход по файловой системе может быть долгим или блокироваться сетевым хранилищем.",
                         "Повторите аудит в период низкой нагрузки и проверьте доступность файловых систем.")
            return
        except OSError as exc:
            self.finding("SUID-001", "SUID", "WARNING", "Не удалось запустить поиск SUID-файлов.",
                         "Проверка не завершена.", "Убедитесь, что доступна команда find.", {"error": str(exc)})
            return
        found = sorted(set(path.strip() for path in proc.stdout.splitlines() if path.strip()))
        unusual = [path for path in found if path not in allowlist]
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
            self.finding("SUID-OK", "SUID", "OK", "Вне базового списка SUID-файлы не найдены.",
                         "Найденные файлы совпадают с базовым allowlist.", "Исправление не требуется.",
                         {"scanned_count": len(found), "allowlist": sorted(allowlist)})

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
        # У разных менеджеров различный формат; отбрасываем WARNING/NOTICE и заголовки.
        names = parse_update_names(lines)
        updates_found = bool(names) and (proc is not None and proc.returncode in (0, 100))
        if updates_found:
            self.finding("UPD-002", "Обновления", "WARNING", "Доступны обновления пакетов ({}).".format(len(names)),
                         "Неустановленные обновления могут содержать исправления известных уязвимостей.",
                         UPDATE_COMMANDS.get(manager, "Обновите систему штатным менеджером пакетов."),
                         {"packages": names, "count": len(names), "package_manager": manager})
        elif proc is None or proc.returncode not in (0, 100):
            self.finding("UPD-001", "Обновления", "WARNING", "Менеджер пакетов не смог проверить обновления.",
                         "Проверка завершилась ошибкой; возможно, нужны права или доступ к репозиториям.",
                         UPDATE_COMMANDS.get(manager, "Проверьте настройки репозиториев."),
                         {"error": proc.stderr.strip() if proc else "команда не запущена"})
        else:
            self.finding("UPD-OK", "Обновления", "OK", "Список ожидающих обновления пакетов пуст.",
                         "Менеджер пакетов не сообщил об обновлениях.", "Исправление не требуется.")

    def check_ssh(self):
        """Проверить активные директивы SSH в основном sshd_config."""
        path = "/etc/ssh/sshd_config"
        try:
            with open(path, encoding="utf-8", errors="replace") as stream:
                lines = stream.readlines()
        except OSError as exc:
            self.finding("SSH-001", "SSH", "WARNING", "Не удалось прочитать sshd_config.",
                         "Настройки удалённого входа остались непроверенными.",
                         "Проверьте OpenSSH Server и файл {}.".format(path), {"error": str(exc)})
            return
        config = {}
        for line in lines:
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2:
                config.setdefault(parts[0].lower(), parts[1].lower())
        root = config.get("permitrootlogin", "default")
        if root == "yes":
            self.finding("SSH-002", "SSH", "CRITICAL", "SSH разрешает прямой вход root.",
                         "Компрометация root-пароля сразу даёт удалённые административные права.",
                         "Установите PermitRootLogin no в sshd_config, затем проверьте конфигурацию и перезапустите sshd.")
        else:
            self.finding("SSH-OK", "SSH", "OK", "Явное PermitRootLogin yes не задано.",
                         "Прямой вход root не разрешён явной директивой yes.", "Исправление не требуется.", {"value": root})
        password = config.get("passwordauthentication", "default")
        if password == "yes":
            self.finding("SSH-003", "SSH", "WARNING", "SSH разрешает парольную аутентификацию.",
                         "Пароли подвержены перебору и повторному использованию; ключи обычно надёжнее.",
                         "После проверки доступа по ключу установите PasswordAuthentication no в sshd_config и перезапустите sshd.")
        else:
            self.finding("SSH-OK", "SSH", "OK", "Явное PasswordAuthentication yes не задано.",
                         "Парольный вход не разрешён явной директивой yes.", "Исправление не требуется.", {"value": password})

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
        print("{}[!] Запущено без прав root. Некоторые проверки будут пропущены.{}\n".format(yellow, reset))


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
            "curl/jammy 7.81 amd64 [upgradable from: 7.80]", "openssl/jammy 3.0 all",
        ])
        self.assertEqual(names, ["curl", "openssl"])

    def test_suid_allowlist_is_defined(self):
        self.assertIn("/usr/bin/passwd", SUID_ALLOWLIST)
        self.assertEqual(SUID_OWNER_COMMANDS["apt"], "dpkg -S")
        self.assertEqual(SUID_OWNER_COMMANDS["dnf"], "rpm -qf")

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
        print("{}║  3. Выход                                           ║{}".format(header, reset))
        print("{}╚════════════════════════════════════════════════════╝{}".format(header, reset))
        try:
            choice = input("Выберите действие [1-3]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nРабота завершена.")
            return 0
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
    if args.menu or (not args.once and not args.json and sys.stdin.isatty() and len(sys.argv) == 1):
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
