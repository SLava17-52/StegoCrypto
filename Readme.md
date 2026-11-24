# Лабораторная работа по исследованию методов стеганографии, шифрования и статистического анализа изображений.


# Зависимости:
Установите библиотеки Python:
```
pip install Pillow cryptography numpy scikit-image scipy matplotlib
```
# Команды запуска

```
python src/lsb.py
```

```
python src/visual.py
```

# Примеры использования в коде:

1) LSB (встраивание и извлечение)

```
from lsb import embed_data, extract_plain_data

# встраиваем наш текст в мессейдж
message = "Привет, мир!"
embed_data("../imgs/akashi.png", "../imgs/stego_plain.png", message.encode('utf-8'), random_pos=False)

# извлечение текста
extracted_text = extract_plain_data("../imgs/stego_plain.png")
print(extracted_text)

```
2) Гибридный режим (AES-GCM + Random LSB)
```
from lsb import embed_data, extract_data, encrypt_message, decrypt_message

# шифруем сообщение перед встраиванием
password = "SecureLabPassword"
secret_text = "Конфиденциальные данные"
salt, nonce, ciphertext = encrypt_message(password, secret_text)

# формируем бинарный пакет полезной нагрузки
payload = salt + nonce + len(ciphertext).to_bytes(4, 'big') + ciphertext

# встраивание в псевдослучайные позиции на основе пароля
embed_data("../imgs/akashi.png", "../imgs/stego_random.png", payload, password=password, random_pos=True)
```
