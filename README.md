# ГОСТ 28147-89 Encryption Tool

Приложение для шифрования и дешифрования сообщений на основе алгоритма ГОСТ 28147-89, реализованное на Python с использованием библиотеки `tkinter` для графического интерфейса.

## Описание

Данное приложение позволяет зашифровать и расшифровать сообщения с использованием алгоритма ГОСТ 28147-89. В приложении реализована поддержка ввода ключа длиной 32 байта, а также возможность шифрования и дешифрования сообщений в формате текста.

### Основные функции:
- **Шифрование сообщений** с использованием алгоритма ГОСТ 28147-89.
- **Дешифрование сообщений**, зашифрованных с использованием того же алгоритма.
- Поддержка произвольных текстовых сообщений.
- Интерфейс на базе `tkinter`.

## Требования

- Python 3.7 или выше
- Библиотека `tkinter` (должна быть установлена по умолчанию вместе с Python)

## Использование

1. Запустите скрипт `main.py`:

    ```bash
    python main.py
    ```

2. Появится графический интерфейс с полями для ввода сообщения и ключа.

3. Введите сообщение в поле "Сообщение" и ключ в поле "Ключ (32 байта)".

4. Нажмите кнопку "Зашифровать" для шифрования сообщения или "Расшифровать" для его дешифрования.

### Пример использования

- Сообщение: `Привет, мир!`
- Ключ: `1234567890abcdef1234567890abcdef`

После шифрования вы получите зашифрованное сообщение в виде шестнадцатеричной строки.

### Пример ключей для тестирования

Ключ должен содержать ровно 32 символа (32 байта). Вот несколько примеров, которые можно использовать:

- `1234567890abcdef1234567890abcdef`
- `A1B2C3D4E5F60718293A4B5C6D7E8F90`
- `qwertyuiopasdfghjklzxcvbnm123456`
- `9f2d34a1b7c8e0ff2a4e6b12f9d0cba3`

## Архитектура программы

Алгоритм ГОСТ 28147-89 реализован с использованием:
- **S-блоков** для замены битов.
- Функции циклического сдвига (ROL).
- Функций для обработки блоков по 8 байт.

### Основные функции:
- `substitute(value)`: замена значений через S-блоки.
- `rol(value, shift)`: циклический сдвиг 32-битного числа.
- `gost_round(left, right, key)`: один раунд шифрования с использованием ключа.
- `gost_encrypt_block(block, key)`: шифрование одного блока данных.
- `gost_decrypt_block(block, key)`: расшифрование одного блока данных.

### Паддинг (Padding)

Реализована функция паддинга для дополнения данных до длины, кратной 8 байтам, с использованием схемы ISO/IEC 7816.
