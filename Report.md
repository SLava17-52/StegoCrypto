# Отчёт

## 1. Постановка задачи
Целью данной работы является исследование изменений свойств цифровых изображений при внедрении скрытых данных методом наименее значимого бита (LSB), а также сравнительный анализ трех вариантов сокрытия информации с помощью статистических показателей и метрик качества

В ходе исследования реализованы и сопоставлены следующие три варианта:

1. **Plain LSB** - встраивание открытого текста путем последовательного обхода пикселей контейнера

2. **Encrypted LSB** - встраивание зашифрованного текста (с использованием симметричного шифрования AES-GCM и производной функции ключа PBKDF2) последовательным обходом

3. **Encrypted Random LSB** - встраивание зашифрованного текста в псевдослучайные позиции, определяемые по ключу-паролю без повторений

**Используемые изображения:** В качестве основного контейнера в эксперименте использовалось пользовательское изображение `akashi.png`, также использовалось предложенное изображение `gradient.png`

**Встраиваемое сообщение:** В качестве основного payload использовалась тестовая строка: `"слово пацана"`

## 2. Реализация

### 2.1. Обычное LSB-встраивание
Встраивание выполняется путем замены младшего бита цветовых компонент (R, G, B) пикселей изображения битами полезной нагрузки. Изменение значения компоненты составляет строго pm 1 или 0

Реализация из `lsb.py`:
- Исходное изображение загружается через `Pillow`, приводится к цветовой модели `RGB` (3 канала по 8 бит на пиксель) и разворачивается в одномерный список значений цветовых компонент
- Полезные данные вместе с 4-байтовым заголовком длины преобразуются в поток бит (от старшего бита байта к младшему)
- Для каждой выбранной компоненты младший бит очищается маской `~1` (`0xFE`) и через побитовое ИЛИ (`|`) заменяется на бит сообщения
- Изменённые компоненты собираются обратно в пиксели и сохраняются в формате `PNG` без сжатия с потерями

```python
def embed_data(
    image_path: str,
    output_path: str,
    data_bytes: bytes,
    password: str = None,
    random_pos: bool = False,
) -> None:
    # Загружаем контейнер и приводим к RGB (3 канала по 8 бит на каждый пиксель)
    img = Image.open(image_path).convert("RGB")
    width, height = img.size
    max_capacity_bits = width * height * 3

    # Добавляем 4-байтовый big-endian префикс длины полезной нагрузки
    framed_data = len(data_bytes).to_bytes(4, "big") + data_bytes
    total_bits_needed = len(framed_data) * 8

    # Проверяем, помещается ли весь пакет (заголовок + данные) в доступные младшие биты
    if total_bits_needed > max_capacity_bits:
        raise ValueError(
            f"Сообщение слишком большое: требуется {total_bits_needed} бит, доступно {max_capacity_bits} бит."
        )

    # Раскладываем каждый байт на 8 бит от старшего (7) к младшему (0)
    bits = [(byte >> bit_idx) & 1 for byte in framed_data for bit_idx in range(7, -1, -1)]

    # Разворачиваем пиксели (RGB) в плоский список цветовых компонент
    flat_channels = []
    for pixel in img.getdata():
        flat_channels.extend(pixel)

    if random_pos:
        indices = _get_shuffled_indices(max_capacity_bits, password)
        # Записываем биты в псевдослучайные позиции без повторений: сбрасываем LSB  и ставим бит 
        for i, bit in enumerate(bits):
            pos = indices[i]
            flat_channels[pos] = (flat_channels[pos] & ~1) | bit
    else:
        # Последовательно записываем биты в младшие биты первых total_bits_needed компонент
        for i, bit in enumerate(bits):
            flat_channels[i] = (flat_channels[i] & ~1) | bit

    # Собираем плоский массив обратно в RGB-пиксели
    new_pixels = [
        (flat_channels[i], flat_channels[i + 1], flat_channels[i + 2])
        for i in range(0, len(flat_channels), 3)
    ]

    # Гарантируем существование каталога вывода и сохраняем в PNG без сжатия с потерями
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    stego_img = Image.new("RGB", (width, height))
    stego_img.putdata(new_pixels)
    stego_img.save(output_path, format="PNG")
```

### 2.2. Хранение длины и проверка вместимости

**Как хранится длина**

Длина полезного блока data_bytes в байтах кодируется в 4-байтное (32-битное) беззнаковое целое число в порядке big-endian (to_bytes(4, "big"))

Пакет для встраивания формируется как [4 байта длины] + [data_bytes]

При извлечении сначала читаются первые 32 младших бита, из них восстанавливается число байт data_len, после чего считываются следующие data_len * 8 бит и собираются обратно в байты

Реализация из `lsb.py`:

```python
framed_data = len(data_bytes).to_bytes(4, "big") + data_bytes

length_bits = [flat_channels[i] & 1 for i in range(32)]
data_len = 0
for b in length_bits:
    data_len = (data_len << 1) | b

total_bits_needed = 32 + data_len * 8
payload_bits = [flat_channels[i] & 1 for i in range(32, total_bits_needed)]
```

**Как проверяется вместимость**: 

При встраивании вычисляется максимальная ёмкость в битах max_capacity_bits = width * height * 3 и сравнивается с total_bits_needed = len(framed_data) * 8; при превышении выбрасывается ValueError
При извлечении проверяется корректность считанной длины data_len и условие total_bits_needed <= max_capacity_bits, чтобы не выйти за пределы изображения при повреждённом заголовке или неверном пароле

Реализация из `lsb.py`:

```python
max_capacity_bits = width * height * 3
framed_data = len(data_bytes).to_bytes(4, "big") + data_bytes
total_bits_needed = len(framed_data) * 8

if total_bits_needed > max_capacity_bits:
    raise ValueError(
        f"Сообщение слишком большое: требуется {total_bits_needed} бит, доступно {max_capacity_bits} бит."
    )
```

### 2.3. Как выполняется шифрование сообщения

Для каждого шифрования генерируются случайная соль salt (16 байт) и случайный nonce (12 байт) через os.urandom()

Из пароля и соли через PBKDF2HMAC (SHA-256) выводится 32-байтный ключ

Сообщение в UTF-8 шифруется через AESGCM(key).encrypt(nonce, plaintext, None), при этом AES-GCM автоматически добавляет тег аутентификации в конец шифротекста

Реализация из `lsb.py` :

```python
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_message(password: str, secret_text: str) -> tuple[bytes, bytes, bytes]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, secret_text.encode("utf-8"), None)
    return salt, nonce, ciphertext
```

### 2.4.Какие служебные данные сохраняются

В Plain LSB: 4 байта длины (big-endian) + байты UTF-8 текста

В Encrypted LSB и Encrypted Random LSB: внутри пакета сохраняются salt (16 байт), nonce (12 байт), 4 байта длины шифротекста и сам ciphertext (AES-GCM), а снаружи embed_data добавляет 4 байта общей длины

Реализация из `lsb.py` :

```python
def pack_encrypted_payload(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return salt + nonce + len(ciphertext).to_bytes(4, "big") + ciphertext


def unpack_encrypted_payload(payload: bytes) -> tuple[bytes, bytes, bytes]:
    salt = payload[:16]
    nonce = payload
    ct_len = int.from_bytes(payload, "big")
    ciphertext = payload[32:32 + ct_len]
    return salt, nonce, ciphertext
```

### 2.5. Как формируется псевдослучайный порядок позиций

От пароля вычисляется хеш SHA-256, который переводится в целое число seed для random.Random(seed)

Создаётся список индексов 0 .. max_capacity_bits - 1 и перемешивается методом rng.shuffle(indices) без повторений

При извлечении по тому же паролю строится та же перестановка indices, поэтому заголовок длины и биты полезной нагрузки читаются из тех же позиций

Реализация из `lsb.py` :

```python
def _get_shuffled_indices(total_bits: int, password: str) -> list[int]:
    if not password:
        raise ValueError("Для псевдослучайного порядка необходим пароль.")
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    seed = int.from_bytes(digest, "big")
    rng = random.Random(seed)
    indices = list(range(total_bits))
    rng.shuffle(indices)
    return indices
```

## 3. Методика эксперимента

1) Объём встраиваемых данных и уровни payload:
   
   Для проверки корректности встраивания, извлечения и расшифрования всех трёх вариантов используется строка "слово пацана" с проверкой assert.
   Для оценки влияния объёма данных сравниваются два уровня заполнения контейнера — 1% и 7% от общей вместимости в битах  (width × height × 3) с учётом служебных полей (4 байта длины, 16 байт salt, 12 байт nonce, 4 байта длины шифротекста, 16 байт тега AES-GCM), с проверкой PSNR, Changed_Ratio(%) и p-value χ²-теста
   
2) Исследуемые изображения

    Сравнение выполнялось на двух изображениях: akashi.png и gradient.png

3) Рассчитываемые метрики

   PSNR и SSIM относительно исходного изображения Cover

   Количество и доля изменённых компонент (Changed_Components, Changed_Ratio(%))

   Распределение младших бит P(LSB=0) и P(LSB=1)

   Статистика χ² по парам соседних значений (2k, 2k+1) с учётом обеих компонент пары

   p-value (df = 127)
 


## 4. Результаты

### 4.1. Сводная таблица метрик - ее можно найти в results/metrics.csv

<img width="1439" height="250" alt="image" src="https://github.com/user-attachments/assets/8da273ee-39ee-41e3-bcd9-961c4e475bfd" />


### 4.2. Результаты для двух уровней payload

Для изображения `akashi.png`:

<img width="745" height="116" alt="image" src="https://github.com/user-attachments/assets/14e118d7-2847-4d4c-a858-4ed2bff8d801" />

Для изображения `gradient.png`:

<img width="716" height="118" alt="image" src="https://github.com/user-attachments/assets/5b951bf4-ca18-4a9f-976d-78ff9dfbd11a" />


### 4.3. Визуализация

## Для изображения `akashi.png`:

Карта разности ее можно найти results/difference.png

<img width="2000" height="1000" alt="histogram" src="https://github.com/user-attachments/assets/1793b105-1393-40a2-bbf3-d695cdb06688" />

Сравнительная гистограмма ее можно найти results/histogram.png

<img width="3000" height="1500" alt="image" src="https://github.com/user-attachments/assets/9227f9e7-6025-49ae-b9d8-ef8310987d8d" />

## Для изображения `gradient.png`:

Карта разности ее можно найти results/difference_gradient.png

<img width="512" height="512" alt="image" src="https://github.com/user-attachments/assets/a6bbc63a-183e-4f8d-8143-0a1620f5c046" />


Сравнительная гистограмма ее можно найти results/histogram_gradient.png

<img width="2000" height="1000" alt="histogram_gradient" src="https://github.com/user-attachments/assets/3c49bcb4-cb75-4f59-a2e2-614f93d54b6a" />


## 5. Анализ

### 5.1. **(PSNR и SSIM):**

На обоих изображениях при небольшом объёме данных значения PSNR высокие, а SSIM близок к 1.0000, поэтому визуально стегоконтейнеры неотличимы от исходных файлов. Гибридные режимы добавляют служебные криптографические поля, из-за чего объём пакета немного больше, чем у открытого текста

### 5.2. **Доля изменённых компонент (`changed_ratio`):**

При замене младшего бита примерно в половине случаев записываемый бит совпадает со старым значением, поэтому Changed_Ratio(%) составляет около половины от доли затронутых бит контейнера

### 5.3. **Распределение LSB **

В Plain LSB доли P(LSB=0) и P(LSB=1) зависят от исходного текста, тогда как шифрование AES-GCM формирует псевдослучайный поток байтов с долями единиц и нулей, близкими к 0.5

### 5.4. **χ²-статистика и p-value:** 
 
Статистика χ² по парам (2k, 2k+1) зависит от исходной гистограммы конкретного изображения (akashi.png и gradient.png ведут себя по-разному из-за разной структуры яркостей), а при увеличении нагрузки сдвиги в парах значений проявляются сильнее

### 5.5. **Влияние шифрования и псевдослучайного размещения:**

Предварительное шифрование через PBKDF2HMAC (SHA-256) и AESGCM скрывает исходный текст и обеспечивает проверку целостности и правильности пароля при расшифровании. В режиме random_pos=True функция _get_shuffled_indices формирует seed из хеша SHA-256 пароля и перемешивает индексы через random.Random(seed).shuffle(...) без повторений, благодаря чему заголовок длины и биты пакета распределяются по всему изображению, а не записываются подряд с начала файла

### 5.6. **Влияние роста полезной нагрузки (Payload):**

Рост payload (1% и 7%) переход от 1% к 7% заполнения закономерно увеличивает число затронутых бит, повышает Changed_Ratio(%) и снижает PSNR


## 6. Итоговый вывод
1) Все три способа встраивания (Plain LSB, Encrypted LSB, Encrypted Random LSB) и обратного восстановления реализованы в src/lsb.py и проверены на совпадение исходного и полученного текста через assert

Реализация из `lsb.py`:

```python
def process_image_suite(cover_path: str, password: str, message: str, prefix: str) -> list[dict]:
    base_dir = os.path.dirname(cover_path)
    plain_path = os.path.join(base_dir, f"stego_{prefix}_plain.png")
    enc_path = os.path.join(base_dir, f"stego_{prefix}_encrypted.png")
    rand_path = os.path.join(base_dir, f"stego_{prefix}_random.png")

    # 1. Встраивание Plain LSB (открытый текст, последовательно)
    embed_data(cover_path, plain_path, message.encode("utf-8"), random_pos=False)

    # 2. Встраивание Encrypted LSB (шифрование AES-GCM, последовательно)
    salt, nonce, ciphertext = encrypt_message(password, message)
    enc_payload = pack_encrypted_payload(salt, nonce, ciphertext)
    embed_data(cover_path, enc_path, enc_payload, random_pos=False)

    # 3. Встраивание Encrypted Random LSB (шифрование AES-GCM, псевдослучайные позиции)
    embed_data(cover_path, rand_path, enc_payload, password=password, random_pos=True)

    # Извлечение и расшифрование для всех трёх вариантов
    restored_plain = extract_plain_text(plain_path)
    restored_enc = extract_encrypted_text(enc_path, password=password, random_pos=False)
    restored_rand = extract_encrypted_text(rand_path, password=password, random_pos=True)

    # Проверка полного совпадения восстановленного текста с исходным
    assert restored_plain == message, f"Несовпадение Plain LSB для {cover_path}"
    assert restored_enc == message, f"Несовпадение Encrypted LSB для {cover_path}"
    assert restored_rand == message, f"Несовпадение Encrypted Random LSB для {cover_path}"
    print(f"[OK] {os.path.basename(cover_path)}: все три варианта извлечены и совпали с исходным текстом.")
```
Внутри вызываются обёртки восстановления, которые читают биты из контейнера (последовательно или по перестановке от пароля) и расшифровывают их:

Реализация из `lsb.py`:
```python
def extract_plain_text(stego_path: str) -> str:
    return extract_data(stego_path, random_pos=False).decode("utf-8")


def extract_encrypted_text(stego_path: str, password: str, random_pos: bool = False) -> str:
    payload = extract_data(stego_path, password=password, random_pos=random_pos)
    salt, nonce, ciphertext = unpack_encrypted_payload(payload)
    return decrypt_message(password, salt, nonce, ciphertext)
```
2) Эксперимент проведен на двух изображениях (akashi.png и gradient.png) и двух уровнях payload (1% и 7%) наглядно показывает, что визуальные искажения при таких уровнях заполнения остаются слабыми, но рост payload прямо влияет на Changed_Ratio(%), PSNR и статистику χ²
3) `visual.py` автоматически формирует карты разности и сравнительные гистограммы для обоих изображений, а src/lsb.py сохраняет сводные метрики в results/metrics.csv

# Общий вывод:

В лабораторной работе реализованы три метода LSB-встраивания данных в RGB-каналы PNG-изображений (Plain LSB, Encrypted LSB и Encrypted Random LSB), а также функции обратного извлечения и расшифрования (extract_data, extract_plain_text, extract_encrypted_text, decrypt_message) с проверкой полного совпадения восстановленного текста с исходным сообщением через assert

Для защиты передаваемых данных применена связка PBKDF2HMAC (SHA-256) и AESGCM с генерацией случайных salt и nonce, упаковкой служебных полей (pack_encrypted_payload / unpack_encrypted_payload) и псевдослучайным распределением позиций по паролю без повторений (_get_shuffled_indices).

Проведён сравнительный эксперимент на изображениях (akashi.png и gradient.png) и двух уровнях заполнения (1% и 7%) с расчётом метрик PSNR, SSIM, числа и доли изменённых компонент (Changed_Components, Changed_Ratio(%)), распределения младших бит (P(LSB=0), P(LSB=1)), статистики χ² по парам соседних значений (2k, 2k+1) и p-value. 
`visual.py` построил карты разности и сравнительные гистограммы, а `lsb.py` сохранил сводные метрики в results/metrics.csv

