import os
import csv
import random
import hashlib
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from skimage.metrics import peak_signal_noise_ratio as compute_psnr
from skimage.metrics import structural_similarity as compute_ssim
from scipy.stats import chi2


#  Криптография (PBKDF2-HMAC-SHA256 + AES-GCM)

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


def decrypt_message(password: str, salt: bytes, nonce: bytes, ciphertext: bytes) -> str:
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def pack_encrypted_payload(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return salt + nonce + len(ciphertext).to_bytes(4, "big") + ciphertext


def unpack_encrypted_payload(payload: bytes) -> tuple[bytes, bytes, bytes]:
    if len(payload) < 32:
        raise ValueError("Некорректный размер зашифрованного пакета.")
    salt = payload[:16]
    nonce = payload[16:28]
    ct_len = int.from_bytes(payload[28:32], "big")
    ciphertext = payload[32:32 + ct_len]
    if len(ciphertext) != ct_len:
        raise ValueError("Повреждён или усечён шифротекст в контейнере.")
    return salt, nonce, ciphertext


#  Встраивание и извлечение LSB

def _get_shuffled_indices(total_bits: int, password: str) -> list[int]:
    if not password:
        raise ValueError("Для псевдослучайного порядка необходим пароль.")
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    seed = int.from_bytes(digest, "big")
    rng = random.Random(seed)
    indices = list(range(total_bits))
    rng.shuffle(indices)
    return indices


def embed_data(
    image_path: str,
    output_path: str,
    data_bytes: bytes,
    password: str = None,
    random_pos: bool = False,
) -> None:
    img = Image.open(image_path).convert("RGB")
    width, height = img.size
    max_capacity_bits = width * height * 3

    # Формат рамки: [4 байта длины data_bytes][data_bytes]
    framed_data = len(data_bytes).to_bytes(4, "big") + data_bytes
    total_bits_needed = len(framed_data) * 8

    if total_bits_needed > max_capacity_bits:
        raise ValueError(
            f"Сообщение большое: требуется {total_bits_needed} бит, доступно {max_capacity_bits} бит."
        )

    bits = [(byte >> bit_idx) & 1 for byte in framed_data for bit_idx in range(7, -1, -1)]

    flat_channels = []
    for pixel in img.getdata():
        flat_channels.extend(pixel)

    if random_pos:
        indices = _get_shuffled_indices(max_capacity_bits, password)
        for i, bit in enumerate(bits):
            pos = indices[i]
            flat_channels[pos] = (flat_channels[pos] & ~1) | bit
    else:
        for i, bit in enumerate(bits):
            flat_channels[i] = (flat_channels[i] & ~1) | bit

    new_pixels = [
        (flat_channels[i], flat_channels[i + 1], flat_channels[i + 2])
        for i in range(0, len(flat_channels), 3)
    ]

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    stego_img = Image.new("RGB", (width, height))
    stego_img.putdata(new_pixels)
    stego_img.save(output_path, format="PNG")


def extract_data(
    stego_path: str,
    password: str = None,
    random_pos: bool = False,
) -> bytes:
    img = Image.open(stego_path).convert("RGB")
    flat_channels = []
    for pixel in img.getdata():
        flat_channels.extend(pixel)

    max_capacity_bits = len(flat_channels)
    if max_capacity_bits < 32:
        raise ValueError("Изображение мало для хранения заголовка длины.")

    if random_pos:
        indices = _get_shuffled_indices(max_capacity_bits, password)
        length_bits = [flat_channels[indices[i]] & 1 for i in range(32)]
    else:
        length_bits = [flat_channels[i] & 1 for i in range(32)]

    data_len = 0
    for b in length_bits:
        data_len = (data_len << 1) | b

    total_bits_needed = 32 + data_len * 8
    if data_len < 0 or total_bits_needed > max_capacity_bits:
        raise ValueError(
            f"Некорректная длина ({data_len} байт) или неверный пароль."
        )

    if random_pos:
        payload_bits = [flat_channels[indices[i]] & 1 for i in range(32, total_bits_needed)]
    else:
        payload_bits = [flat_channels[i] & 1 for i in range(32, total_bits_needed)]

    result = bytearray()
    for i in range(0, len(payload_bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | payload_bits[i + j]
        result.append(byte)

    return bytes(result)


def extract_plain_text(stego_path: str) -> str:
    return extract_data(stego_path, random_pos=False).decode("utf-8")


def extract_encrypted_text(stego_path: str, password: str, random_pos: bool = False) -> str:
    payload = extract_data(stego_path, password=password, random_pos=random_pos)
    salt, nonce, ciphertext = unpack_encrypted_payload(payload)
    return decrypt_message(password, salt, nonce, ciphertext)


#  Статистический анализ

def compute_lsb_stats(arr: np.ndarray) -> tuple[float, float, float, float]:
    lsbs = arr & 1
    p0 = float(np.mean(lsbs == 0))
    p1 = float(np.mean(lsbs == 1))

    flat = arr.flatten()
    chi2_stat = 0.0
    # Для каждой пары (2k, 2k+1) ожидаемое число при равномерном LSB равно (n_2k + n_{2k+1}) / 2.
    # Суммируем вклад обеих компонент пары: ((n_2k - m)^2 + (n_{2k+1} - m)^2) / m = 2 * (n_2k - m)^2 / m.
    for k in range(0, 256, 2):
        n_even = float(np.sum(flat == k))
        n_odd = float(np.sum(flat == k + 1))
        expected = (n_even + n_odd) / 2.0
        if expected > 0.0:
            chi2_stat += 2.0 * ((n_even - expected) ** 2) / expected

    p_val = float(1.0 - chi2.cdf(chi2_stat, df=127))
    return p0, p1, chi2_stat, p_val


def run_statistical_analysis(cover_path: str, stego_paths: dict[str, str]) -> list[dict]:
    cover_arr = np.array(Image.open(cover_path).convert("RGB"), dtype=np.int16)
    total_components = cover_arr.size

    rows = []
    p0, p1, c_stat, p_val = compute_lsb_stats(cover_arr)
    rows.append({
        "Image": os.path.basename(cover_path),
        "Variant": "Cover",
        "PSNR": "-",
        "SSIM": "-",
        "Changed_Components": 0,
        "Changed_Ratio(%)": "-",
        "P(LSB=0)": f"{p0:.4f}",
        "P(LSB=1)": f"{p1:.4f}",
        "Chi2": f"{c_stat:.2f}",
        "p-value": f"{p_val:.4f}",
    })

    for name, path in stego_paths.items():
        stego_arr = np.array(Image.open(path).convert("RGB"), dtype=np.int16)
        psnr = float(compute_psnr(cover_arr, stego_arr, data_range=255))
        ssim = float(compute_ssim(cover_arr, stego_arr, channel_axis=2, data_range=255))
        changed_count = int(np.sum(cover_arr != stego_arr))
        changed_ratio = (changed_count / total_components) * 100.0
        p0_s, p1_s, c_s, pv_s = compute_lsb_stats(stego_arr)

        rows.append({
            "Image": os.path.basename(cover_path),
            "Variant": name,
            "PSNR": f"{psnr:.2f}",
            "SSIM": f"{ssim:.4f}",
            "Changed_Components": changed_count,
            "Changed_Ratio(%)": f"{changed_ratio:.4f}",
            "P(LSB=0)": f"{p0_s:.4f}",
            "P(LSB=1)": f"{p1_s:.4f}",
            "Chi2": f"{c_s:.2f}",
            "p-value": f"{pv_s:.4f}",
        })

    print(
        f"\n=== Статистика для {os.path.basename(cover_path)} (компонент: {total_components}) ==="
    )
    print(
        f"{'Вариант':<22} | {'PSNR':<6} | {'SSIM':<6} | {'Changed':<8} | "
        f"{'Ratio(%)':<9} | {'P(LSB=1)':<8} | {'Chi2':<10} | {'p-value':<8}"
    )
    print("-" * 98)
    for r in rows:
        print(
            f"{r['Variant']:<22} | {str(r['PSNR']):<6} | {str(r['SSIM']):<6} | "
            f"{str(r['Changed_Components']):<8} | {str(r['Changed_Ratio(%)']):<9} | "
            f"{r['P(LSB=1)']:<8} | {r['Chi2']:<10} | {r['p-value']:<8}"
        )

    return rows


def run_payload_comparison(cover_path: str, password: str) -> list[dict]:
    cover_arr = np.array(Image.open(cover_path).convert("RGB"), dtype=np.int16)
    total_components = cover_arr.size  # 1 бит на компоненту
    # Служебные поля внутри рамки embed_data:
    # 4 байта длины payload + 16 байт salt + 12 байт nonce + 4 байта len(ct) + 16 байт тега AES-GCM = 52 байта
    overhead_bytes = 4 + 16 + 12 + 4 + 16

    levels = [0.01, 0.07]  # 1% и 7% ёмкости
    results = []
    temp_path = os.path.join(os.path.dirname(cover_path), "_temp_payload_test.png")

    print(
        f"\n=== Сравнение уровней payload (1% и 7%, Encrypted Random LSB) на {os.path.basename(cover_path)} ==="
    )
    print(
        f"{'Уровень':<10} | {'Framed_B':<9} | {'Bits_Used':<9} | {'PSNR':<7} | "
        f"{'Ratio(%)':<9} | {'Chi2':<10} | {'p-value':<8}"
    )
    print("-" * 88)

    try:
        for ratio in levels:
            target_framed_bytes = max(overhead_bytes + 1, int((total_components * ratio) // 8))
            secret_len = target_framed_bytes - overhead_bytes
            secret_bytes = os.urandom(secret_len)

            salt = os.urandom(16)
            nonce = os.urandom(12)
            key = derive_key(password, salt)
            ct = AESGCM(key).encrypt(nonce, secret_bytes, None)
            framed = pack_encrypted_payload(salt, nonce, ct)

            embed_data(cover_path, temp_path, framed, password=password, random_pos=True)
            stego_arr = np.array(Image.open(temp_path).convert("RGB"), dtype=np.int16)

            actual_framed_bytes = len(framed) + 4  # +4 байта заголовка длины в embed_data
            bits_used = actual_framed_bytes * 8
            psnr = float(compute_psnr(cover_arr, stego_arr, data_range=255))
            changed_ratio = (float(np.sum(cover_arr != stego_arr)) / total_components) * 100.0
            _, _, c_stat, p_val = compute_lsb_stats(stego_arr)

            label = f"{int(ratio * 100)}%"
            results.append({
                "Image": os.path.basename(cover_path),
                "Payload_Level": label,
                "Framed_Bytes": actual_framed_bytes,
                "Bits_Used": bits_used,
                "PSNR": f"{psnr:.2f}",
                "Changed_Ratio(%)": f"{changed_ratio:.4f}",
                "Chi2": f"{c_stat:.2f}",
                "p-value": f"{p_val:.4f}",
            })
            print(
                f"{label:<10} | {actual_framed_bytes:<9} | {bits_used:<9} | {psnr:<7.2f} | "
                f"{changed_ratio:<9.4f} | {c_stat:<10.2f} | {p_val:<8.4f}"
            )
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return results


def process_image_suite(cover_path: str, password: str, message: str, prefix: str) -> list[dict]:
    base_dir = os.path.dirname(cover_path)
    plain_path = os.path.join(base_dir, f"stego_{prefix}_plain.png")
    enc_path = os.path.join(base_dir, f"stego_{prefix}_encrypted.png")
    rand_path = os.path.join(base_dir, f"stego_{prefix}_random.png")

    # 1. Plain LSB
    embed_data(cover_path, plain_path, message.encode("utf-8"), random_pos=False)

    # 2. Encrypted LSB
    salt, nonce, ciphertext = encrypt_message(password, message)
    enc_payload = pack_encrypted_payload(salt, nonce, ciphertext)
    embed_data(cover_path, enc_path, enc_payload, random_pos=False)

    # 3. Encrypted Random LSB
    embed_data(cover_path, rand_path, enc_payload, password=password, random_pos=True)

    # Проверка извлечения и расшифрования всех трёх вариантов
    restored_plain = extract_plain_text(plain_path)
    restored_enc = extract_encrypted_text(enc_path, password=password, random_pos=False)
    restored_rand = extract_encrypted_text(rand_path, password=password, random_pos=True)

    assert restored_plain == message, f"Несовпадение Plain LSB для {cover_path}"
    assert restored_enc == message, f"Несовпадение Encrypted LSB для {cover_path}"
    assert restored_rand == message, f"Несовпадение Encrypted Random LSB для {cover_path}"
    print(f"[OK] {os.path.basename(cover_path)}: все три варианта извлечены и совпали с исходным текстом.")

    stego_map = {
        "Plain LSB": plain_path,
        "Encrypted LSB": enc_path,
        "Encrypted Random LSB": rand_path,
    }
    rows = run_statistical_analysis(cover_path, stego_map)
    run_payload_comparison(cover_path, password)
    return rows


if __name__ == "__main__":
    pwd = "SecretLabPassword"
    msg = "слово пацана"

    images_to_test = [
        ("../imgs/akashi.png", "akashi"),
        ("../imgs/gradient.png", "gradient"),
    ]

    all_rows = []
    for img_path, tag in images_to_test:
        if os.path.exists(img_path):
            all_rows.extend(process_image_suite(img_path, pwd, msg, tag))
        else:
            print(f"[WARN] Файл не найден и пропущен: {img_path}")

    if all_rows:
        os.makedirs("../results", exist_ok=True)
        out_csv = "../results/metrics.csv"
        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
            writer.writeheader()
            writer.writerows(all_rows)
        print(f"\n[OK] Сводные метрики сохранены в {out_csv}")