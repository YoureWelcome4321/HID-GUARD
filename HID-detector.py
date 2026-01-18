import ctypes
import sys
import re
import customtkinter as ctk
from tkinter import messagebox
import winreg
import wmi
import subprocess
import threading

# ----------------------------
# Настройки
# ----------------------------
MASTER_PASSWORD = "admin123"  # ← ЗАМЕНИТЕ НА СВОЙ!
POLICY_BASE = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
ALLOW_LIST_KEY = POLICY_BASE + r"\AllowList"

# ----------------------------
# Win32 API
# ----------------------------
from ctypes import wintypes

DIF_REMOVE = 0x00000005
DI_REMOVEDEVICE_GLOBAL = 0x00000004
DIGCF_ALLCLASSES = 0x00000004

class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("ClassGuid", wintypes.BYTE * 16),
        ("DevInst", wintypes.DWORD),
        ("Reserved", ctypes.POINTER(wintypes.ULONG)),
    ]

class SP_REMOVEDEVICE_PARAMS(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("InstallFunction", wintypes.DWORD),
        ("Scope", wintypes.DWORD),
        ("HwProfile", wintypes.DWORD),
    ]

setupapi = ctypes.windll.setupapi
cfgmgr32 = ctypes.windll.cfgmgr32

setupapi.SetupDiGetClassDevsW.argtypes = [
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    wintypes.HWND,
    wintypes.DWORD,
]
setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE

setupapi.SetupDiEnumDeviceInfo.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(SP_DEVINFO_DATA),
]
setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL

setupapi.SetupDiCallClassInstaller.argtypes = [
    wintypes.DWORD,
    wintypes.HANDLE,
    ctypes.POINTER(SP_DEVINFO_DATA),
]
setupapi.SetupDiCallClassInstaller.restype = wintypes.BOOL

setupapi.SetupDiSetClassInstallParamsW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(SP_DEVINFO_DATA),
    ctypes.c_void_p,
    wintypes.DWORD,
]
setupapi.SetupDiSetClassInstallParamsW.restype = wintypes.BOOL

setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

cfgmgr32.CM_Get_Device_IDW.argtypes = [
    wintypes.DWORD,
    wintypes.LPWSTR,
    wintypes.ULONG,
    wintypes.ULONG,
]
cfgmgr32.CM_Get_Device_IDW.restype = wintypes.DWORD

def remove_all_usb_devices():
    hdevinfo = setupapi.SetupDiGetClassDevsW(None, None, None, DIGCF_ALLCLASSES)
    INVALID_HANDLE_VALUE = -1
    if hdevinfo == INVALID_HANDLE_VALUE:
        return

    try:
        index = 0
        while True:
            devinfo = SP_DEVINFO_DATA()
            devinfo.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
            if not setupapi.SetupDiEnumDeviceInfo(hdevinfo, index, ctypes.byref(devinfo)):
                break

            buf = ctypes.create_unicode_buffer(512)
            if cfgmgr32.CM_Get_Device_IDW(devinfo.DevInst, buf, 512, 0) == 0:
                hwid = buf.value.upper()
                if "VID_" in hwid and "PID_" in hwid:
                    remove_params = SP_REMOVEDEVICE_PARAMS()
                    remove_params.cbSize = ctypes.sizeof(SP_REMOVEDEVICE_PARAMS)
                    remove_params.InstallFunction = DIF_REMOVE
                    remove_params.Scope = DI_REMOVEDEVICE_GLOBAL
                    remove_params.HwProfile = 0
                    setupapi.SetupDiSetClassInstallParamsW(
                        hdevinfo, ctypes.byref(devinfo), ctypes.byref(remove_params), remove_params.cbSize
                    )
                    setupapi.SetupDiCallClassInstaller(DIF_REMOVE, hdevinfo, ctypes.byref(devinfo))
            index += 1
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(hdevinfo)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

def set_policy_deny(deny: bool):
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, POLICY_BASE) as key:
        winreg.SetValueEx(key, "DenyUnspecified", 0, winreg.REG_DWORD, 1 if deny else 0)

def clear_allow_list():
    try:
        winreg.DeleteKeyEx(winreg.HKEY_LOCAL_MACHINE, ALLOW_LIST_KEY, winreg.KEY_WOW64_64KEY, 0)
    except FileNotFoundError:
        pass
    except OSError:
        pass
    winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, ALLOW_LIST_KEY, 0, winreg.KEY_WOW64_64KEY)

def add_to_allow_list(hwid: str):
    access = winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ALLOW_LIST_KEY, 0, access) as key:
        index = 0
        while True:
            try:
                winreg.EnumValue(key, index)
                index += 1
            except OSError:
                break
        winreg.SetValueEx(key, str(index), 0, winreg.REG_SZ, hwid)

VENDOR_MAP = {
    "03F0": "HP", "045E": "Microsoft", "046D": "Logitech", "04B3": "IBM",
    "04B4": "Cypress", "05AC": "Apple", "093A": "Pixart Imaging",
    "0A5C": "Broadcom", "1050": "Yubico", "13BA": "PCPlay",
    "17EF": "Lenovo", "1A2C": "China Resource Semico",
    "1BCF": "Sunplus Innovation", "2341": "Arduino",
    "1B4F": "SparkFun", "16C0": "VOTI", "16D0": "Digistump",
    "27BB": "3D Robotics", "04D8": "Microchip", "1D50": "OpenMoko",
    "1DDF": "STMicroelectronics", "0483": "STMicroelectronics",
    "0403": "FTDI", "11A0": "Atmel", "239A": "Adafruit",
    "1B1C": "Corsair", "1038": "SteelSeries", "1044": "Dell"
}

def get_vendor_name(vid_hex: str) -> str:
    return VENDOR_MAP.get(vid_hex.upper(), "Unknown Vendor")

def get_current_hid_devices():
    devices = []
    seen_vid_pid = set()
    try:
        c = wmi.WMI()
        for dev in c.Win32_PnPEntity():
            pnp = dev.PNPDeviceID
            if not pnp:
                continue
            pnp = pnp.upper()
            if "VID_" in pnp and "PID_" in pnp:
                if not any(marker in pnp for marker in ["HID\\", "USB\\VID_"]):
                    continue
                name = (dev.Name or dev.Description or "Unknown HID").strip()
                if not name or len(name) < 3:
                    continue
                name_lower = name.lower()
                exclude_keywords = [
                    "internal", "built-in", "встроен", "camera", "webcam", "imaging",
                    "touchpad", "trackpad", "synaptics", "elan", "system controller",
                    "composite", "root", "generic", "parent", "hub", "usb root hub",
                    "веб-камера", "микросхема", "датчик", "intel", "nvidia", "realtek",
                    "microsoft", "hid-compliant consumer control", "system audio",
                    "consumer control", "wireless", "bluetooth", "hid-compliant system"
                ]
                if any(kw in name_lower for kw in exclude_keywords):
                    continue
                vid_pid_match = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", pnp)
                if not vid_pid_match:
                    continue
                vid = vid_pid_match.group(1)
                pid = vid_pid_match.group(2)
                key = f"{vid}_{pid}"
                if key not in seen_vid_pid:
                    seen_vid_pid.add(key)
                    vendor = get_vendor_name(vid)
                    display_name = f"{name}\n   {vendor} (VID_{vid}:PID_{pid})"
                    devices.append((display_name, pnp))
    except Exception as e:
        print("WMI error:", e)
    return devices

# ----------------------------
# Исправленные кастомные диалоги
# ----------------------------

class CustomDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Диалог", message="", icon="ℹ️", confirm_text="OK", cancel_text=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("500x260")
        self.resizable(False, False)
        self.result = False
        self.grab_set()
        
        # Заголовок окна
        header_frame = ctk.CTkFrame(self, fg_color="#1a1d1e", corner_radius=0)
        header_frame.pack(fill="x")
        ctk.CTkLabel(
            header_frame,
            text=title,
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#4FC3F7"
        ).pack(pady=12)
        
        # Основное содержимое
        content_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        content_frame.pack(pady=20, padx=25, fill="both", expand=True)
        
        icon_label = ctk.CTkLabel(
            content_frame,
            text=icon,
            font=ctk.CTkFont(size=48, weight="bold"),
            text_color="#4FC3F7"
        )
        icon_label.pack(pady=(0, 15))
        
        message_label = ctk.CTkLabel(
            content_frame,
            text=message,
            font=ctk.CTkFont(size=13),
            text_color="#e0e0e0",
            wraplength=450,
            justify="center"
        )
        message_label.pack(pady=(0, 25))
        
        # Кнопки
        btn_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        btn_frame.pack(pady=(0, 20))
        
        # Кнопка отмены (если указана)
        if cancel_text:
            ctk.CTkButton(
                btn_frame,
                text=cancel_text,
                width=120,
                height=36,
                fg_color="#444",
                hover_color="#333",
                text_color="#ffffff",
                font=ctk.CTkFont(size=13, weight="bold"),
                command=self.cancel
            ).pack(side="left", padx=15)
        
        # Кнопка подтверждения (всегда есть)
        ctk.CTkButton(
            btn_frame,
            text=confirm_text,
            width=120,
            height=36,
            fg_color="#1E88E5",
            hover_color="#1976D2",
            text_color="#ffffff",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.confirm
        ).pack(side="left", padx=15)
        
        self.after(100, self.lift)

    def confirm(self):
        self.result = True
        self.destroy()

    def cancel(self):
        self.result = False
        self.destroy()

    def wait_result(self):
        self.wait_window()
        return self.result

class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("🔒 Аутентификация безопасности")
        self.geometry("420x210")
        self.resizable(False, False)
        self.password = None
        self.grab_set()
        
        ctk.CTkLabel(
            self,
            text="Требуется мастер-пароль",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#4FC3F7"
        ).pack(pady=(25, 10))
        
        ctk.CTkLabel(
            self,
            text="Для изменения настроек безопасности введите пароль:",
            font=ctk.CTkFont(size=12),
            text_color="#aaa"
        ).pack(pady=(0, 20))

        self.entry = ctk.CTkEntry(
            self,
            width=340,
            show="●",
            font=ctk.CTkFont(size=13),
            placeholder_text="Введите мастер-пароль...",
            fg_color="#2a2d2e",
            text_color="#e0e0e0",
            border_color="#4FC3F7",
            border_width=2
        )
        self.entry.pack(pady=5)
        self.entry.bind("<Return>", lambda e: self.confirm())
        self.entry.focus()

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=22)
        
        ctk.CTkButton(
            btn_frame,
            text="Подтвердить",
            width=120,
            height=36,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1E88E5",
            hover_color="#1976D2",
            text_color="#ffffff",
            command=self.confirm
        ).pack(side="left", padx=12)
        
        ctk.CTkButton(
            btn_frame,
            text="Отмена",
            width=120,
            height=36,
            font=ctk.CTkFont(size=13),
            fg_color="#444",
            hover_color="#333",
            text_color="#ffffff",
            command=self.cancel
        ).pack(side="left", padx=12)

        self.after(100, self.lift)

    def confirm(self):
        self.password = self.entry.get()
        self.destroy()

    def cancel(self):
        self.password = None
        self.destroy()

# ----------------------------
# Главное окно
# ----------------------------

class BadUSBHIDGuard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("HID Guard — Защита от аппаратных атак")
        self.geometry("860x640")
        self.minsize(820, 600)
        self.configure(fg_color="#121212")
        
        self.ACCENT_COLOR = "#4FC3F7"
        self.PRIMARY_COLOR = "#1E88E5"
        self.SUCCESS_COLOR = "#4CAF50"
        self.WARNING_COLOR = "#FFA726"
        self.DANGER_COLOR = "#EF5350"

        self.create_widgets()
        self.update_devices_display()

    def create_widgets(self):
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(pady=25)
        
        ctk.CTkLabel(
            header_frame,
            text="HID GUARD",
            font=ctk.CTkFont(family="Segoe UI", size=36, weight="bold"),
            text_color=self.ACCENT_COLOR
        ).pack()
        
        ctk.CTkLabel(
            header_frame,
            text="Промышленная защита от BadUSB, Rubber Ducky и HID-угроз",
            font=ctk.CTkFont(family="Segoe UI", size=15),
            text_color="#aaa"
        ).pack(pady=(10, 0))

        self.status_frame = ctk.CTkFrame(
            self, 
            corner_radius=14, 
            fg_color="#1a1a1a",
            border_width=2,
            border_color=self.ACCENT_COLOR
        )
        self.status_frame.pack(pady=15, padx=50, fill="x")
        
        self.status_icon = ctk.CTkLabel(
            self.status_frame, 
            text="●", 
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=self.ACCENT_COLOR
        )
        self.status_icon.pack(side="left", padx=25, pady=15)
        
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="Система готова к защите",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=self.ACCENT_COLOR
        )
        self.status_label.pack(side="left", pady=15)

        list_container = ctk.CTkFrame(self, corner_radius=16, fg_color="transparent")
        list_container.pack(pady=20, padx=50, fill="both", expand=True)

        list_header = ctk.CTkFrame(list_container, fg_color="transparent")
        list_header.pack(fill="x", padx=8, pady=(0, 15))
        
        ctk.CTkLabel(
            list_header,
            text="Доверенные HID-устройства",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=self.ACCENT_COLOR
        ).pack(side="left")
        
        self.count_label = ctk.CTkLabel(
            list_header,
            text="(0)",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=self.ACCENT_COLOR
        )
        self.count_label.pack(side="left", padx=(8, 0))

        self.devices_listbox = ctk.CTkTextbox(
            list_container,
            font=ctk.CTkFont(family="Consolas", size=13),
            corner_radius=14,
            fg_color="#1e1e1e",
            text_color="#e0e0e0",
            border_color="#333",
            border_width=2,
            wrap="none"
        )
        self.devices_listbox.pack(fill="both", expand=True, padx=2, pady=(0, 10))
        self.devices_listbox.insert("0.0", 
            "🕗 Ожидание активации режима добавления...\n\n"
            "Нажмите кнопку ниже, чтобы начать настройку защиты."
        )
        self.devices_listbox.configure(state="disabled")

        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=20)

        self.start_btn = ctk.CTkButton(
            button_frame,
            text="⚡ Активировать режим добавления",
            width=300,
            height=50,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=self.PRIMARY_COLOR,
            hover_color="#1565C0",
            text_color="#ffffff",
            command=self.start_registration
        )
        self.start_btn.pack(side="left", padx=15)

        self.finish_btn = ctk.CTkButton(
            button_frame,
            text="🔒 Активировать защиту",
            width=300,
            height=50,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=self.DANGER_COLOR,
            hover_color="#D32F2F",
            text_color="#ffffff",
            command=self.finish_registration
        )
        self.finish_btn.pack(side="left", padx=15)

        instruction_text = (
            "ИНСТРУКЦИЯ:\n"
            "1. Нажмите «Активировать режим добавления» и введите пароль\n"
            "2. Подключите ДОВЕРЕННЫЕ устройства (мышь, клавиатуру, токены)\n"
            "3. Нажмите «Активировать защиту» — все остальные HID будут заблокированы"
        )
        ctk.CTkLabel(
            self,
            text=instruction_text,
            text_color="#777",
            justify="left",
            font=ctk.CTkFont(size=13),
            wraplength=800
        ).pack(pady=(15, 25))

    def update_status(self, text: str, color: str, icon: str = "●"):
        self.status_label.configure(text=text, text_color=color)
        self.status_icon.configure(text=icon, text_color=color)

    def update_devices_display(self):
        devices = get_current_hid_devices()
        self.devices_listbox.configure(state="normal")
        self.devices_listbox.delete("0.0", "end")
        self.count_label.configure(text=f"({len(devices)})")
        
        if not devices:
            self.devices_listbox.insert("0.0", 
                "🕗 Ожидание подключения внешних HID-устройств...\n\n"
                "Подключите:\n"
                " • USB-клавиатуру\n"
                " • USB-мышь\n"
                " • Токены безопасности (YubiKey и др.)\n"
                " • Другие доверенные HID-устройства"
            )
        else:
            self.devices_listbox.insert("0.0", "Текущие доверенные устройства:\n\n")
            for i, (display_name, _) in enumerate(devices, 1):
                self.devices_listbox.insert("end", f"{i}. {display_name}\n\n")
        
        self.devices_listbox.configure(state="disabled")

    def ask_password(self):
        dialog = PasswordDialog(self)
        self.wait_window(dialog)
        return dialog.password

    def show_info(self, title, message):
        dialog = CustomDialog(self, title=title, message=message, icon="✅", confirm_text="Понятно")
        dialog.wait_result()

    def ask_confirmation(self, title, message, confirm_text="Подтвердить", cancel_text="Отмена"):
        dialog = CustomDialog(self, title=title, message=message, icon="⚠️", 
                             confirm_text=confirm_text, cancel_text=cancel_text)
        return dialog.wait_result()

    def show_error(self, title, message):
        messagebox.showerror(title, message)

    def start_registration(self):
        password = self.ask_password()
        if password != MASTER_PASSWORD:
            self.show_error("Ошибка аутентификации", "Неверный мастер-пароль!")
            return

        self.update_status("Подготовка к очистке...", self.WARNING_COLOR, "🔄")
        self.start_btn.configure(state="disabled")
        self.finish_btn.configure(state="disabled")
        
        def run_removal():
            try:
                remove_all_usb_devices()
                set_policy_deny(False)
                self.after(0, lambda: self.show_info(
                    "Режим добавления активирован",
                    "✅ Все старые устройства удалены.\n\n"
                    "🟢 Теперь подключите ДОВЕРЕННЫЕ HID-устройства.\n"
                    "Список обновится автоматически через 2 секунды."
                ))
                self.after(0, lambda: self.update_status(
                    "Режим добавления активен — подключите устройства", 
                    self.SUCCESS_COLOR, 
                    "🟢"
                ))
                self.after(2000, self.update_devices_display)
            except Exception as e:
                self.after(0, lambda: self.show_error("Ошибка", f"Не удалось активировать режим добавления:\n{str(e)}"))
            finally:
                self.after(0, lambda: (
                    self.start_btn.configure(state="normal"),
                    self.finish_btn.configure(state="normal")
                ))
        
        threading.Thread(target=run_removal, daemon=True).start()

    def finish_registration(self):
        devices = get_current_hid_devices()
        
        has_input = any(
            any(kw in name.lower() for kw in ["keyboard", "mouse", "клавиатура", "мышь", "hid-compliant"])
            for name, _ in devices
        )

        if not devices:
            summary = "❗ ВНИМАНИЕ: Ни одно HID-устройство не выбрано!\n\n"
            summary += "После активации ВСЕ HID-устройства будут заблокированы.\n"
            summary += "Это может привести к потере управления системой!\n\n"
        else:
            summary = "Будут разрешены следующие устройства:\n\n"
            for name, _ in devices:
                summary += f"• {name}\n\n"
            if not has_input:
                summary += "❗ ВНИМАНИЕ: Среди устройств нет клавиатуры или мыши!\n"
                summary += "Вы можете потерять управление системой после активации!\n\n"

        summary += "Все остальные HID-устройства будут ЗАБЛОКИРОВАНЫ с ошибкой:\n"
        summary += "«Установка этого устройства запрещена»\n\n"
        summary += "АКТИВИРОВАТЬ ЗАЩИТУ?"

        # 🔑 ИСПРАВЛЕНО: теперь есть ОБЕ кнопки, и окно работает
        if not self.ask_confirmation("Подтверждение активации защиты", summary, "Активировать", "Отмена"):
            return

        self.update_status("Активация защиты...", self.WARNING_COLOR, "⏳")
        self.start_btn.configure(state="disabled")
        self.finish_btn.configure(state="disabled")
        
        try:
            clear_allow_list()
            for _, hwid in devices:
                add_to_allow_list(hwid)
            set_policy_deny(True)
            subprocess.run("pnputil /scan-devices", shell=True, capture_output=True)
            
            self.show_info(
                "Защита успешно активирована!", 
                f"✅ Разрешено: {len(devices)} устройств.\n\n"
                "Теперь:\n"
                " • Доверенные устройства будут работать\n"
                " • Все новые HID (Arduino, BadUSB и т.д.) — ЗАБЛОКИРОВАНЫ"
            )
            self.update_status("Защита активна — все неопознанные HID заблокированы", self.DANGER_COLOR, "🔒")
            self.update_devices_display()
        except Exception as e:
            self.show_error("Критическая ошибка", f"Не удалось активировать защиту:\n{str(e)}")
        finally:
            self.start_btn.configure(state="normal")
            self.finish_btn.configure(state="normal")

# ----------------------------
# Запуск
# ----------------------------
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = BadUSBHIDGuard()
    app.mainloop()