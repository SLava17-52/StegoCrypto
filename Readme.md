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

1) LSB 

```
from lsb import embed_data, extract_plain_text

embed_data(
    "../imgs/akashi.png",
    "../imgs/stego_plain.png",
    "слово пацана".encode("utf-8"),
    random_pos=False,
)

restored_plain = extract_plain_text("../imgs/stego_plain.png")
print(restored_plain)

```
2) Гибридный режим (AES-GCM + Random LSB)
```
from lsb import embed_data, encrypt_message, pack_encrypted_payload

password = "SecretLabPassword"
salt, nonce, ciphertext = encrypt_message(password, "слово пацана")
payload = pack_encrypted_payload(salt, nonce, ciphertext)

embed_data(
    "../imgs/akashi.png",
    "../imgs/stego_random.png",
    payload,
    password=password,
    random_pos=True,
)
```
3) Извлечения и расшифрования

```
from lsb import extract_encrypted_text

password = "SecretLabPassword"

# Последовательный зашифрованный режим
text_enc = extract_encrypted_text("../imgs/stego_encrypted.png", password=password, random_pos=False)

# Псевдослучайный зашифрованный режим
text_rand = extract_encrypted_text("../imgs/stego_random.png", password=password, random_pos=True)

print(text_enc)
print(text_rand)
```
