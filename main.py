import pefile
from capstone import *
import sys
import os

def get_architecture(pe):
    """
    Определяет архитектуру PE файла

    Args:
        pe: Объект PE файла

    Returns:
        tuple: (режим Capstone, строка с описанием архитектуры)
    """
    if hasattr(pe, 'FILE_HEADER'):
        machine = pe.FILE_HEADER.Machine

        if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return CS_MODE_32, "x86 (32-bit)"
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return CS_MODE_64, "x64 (64-bit)"
        else:
            raise Exception(f"Неподдерживаемая архитектура: {hex(machine)}")

    raise Exception("Невозможно определить архитектуру")

def disassemble_exe(exe_path):
    """
    Дизассемблирует .exe файл и сохраняет ассемблерный код

    Args:
        exe_path (str): Путь к .exe файлу
    """
    try:
        # Создаём имя выходного файла
        base_name = os.path.splitext(os.path.basename(exe_path))[0]
        output_path = f"{base_name}_disasm.asm"

        # Загружаем .exe файл
        pe = pefile.PE(exe_path)

        # Определяем архитектуру
        mode, arch_name = get_architecture(pe)
        print(f"Обнаружена архитектура: {arch_name}")

        # Инициализируем дизассемблер с правильной архитектурой
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        with open(output_path, 'w', encoding='utf-8') as f:
            # Записываем информацию о файле
            f.write(f"; Файл: {os.path.basename(exe_path)}\n")
            f.write(f"; Архитектура: {arch_name}\n")
            f.write(f"; Точка входа: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}\n")
            f.write(f"; ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:08x}\n\n")

            # Проходим по каждой секции
            for section in pe.sections:
                if section.IMAGE_SCN_MEM_EXECUTE:  # Проверяем, является ли секция исполняемой
                    section_name = section.Name.decode().strip('\x00')
                    f.write(f"\n;{'=' * 50}\n")
                    f.write(f";Section: {section_name}\n")
                    f.write(f";Virtual Address: 0x{section.VirtualAddress:08x}\n")
                    f.write(f";Size: 0x{section.Misc_VirtualSize:08x}\n")
                    f.write(f";{'=' * 50}\n\n")

                    # Получаем данные секции
                    code = section.get_data()

                    # Получаем виртуальный адрес секции
                    address = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase

                    # Дизассемблируем код
                    for insn in md.disasm(code, address):
                        # Форматируем и записываем инструкции
                        bytes_str = ' '.join([f'{b:02x}' for b in insn.bytes])
                        line = f"0x{insn.address:08x}: {bytes_str:24} {insn.mnemonic:8} {insn.op_str}\n"
                        f.write(line)

        print(f"Дизассемблирование завершено. Результат сохранен в {output_path}")
        return True

    except Exception as e:
        print(f"Ошибка при дизассемблировании: {str(e)}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Использование: python disassembler.py <путь_к_exe>")
        return

    exe_path = sys.argv[1]

    if not os.path.exists(exe_path):
        print(f"Файл {exe_path} не найден")
        return

    print("Начало дизассемблирования...")
    disassemble_exe(exe_path)

if __name__ == "__main__":
    main()
