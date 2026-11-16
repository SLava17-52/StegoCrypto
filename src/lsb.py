import os
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


# Криптографические функции (AES-GCM + PBKDF2)
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_message(password: str, secret_text: str) -> tuple[bytes, bytes, bytes]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, secret_text.encode('utf-8'), None)
    return salt, nonce, ciphertext


def decrypt_message(password: str, salt: bytes, nonce: bytes, ciphertext: bytes) -> str:
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')


# встраивание и извлечение

def embed_data(image_path: str, output_path: str, data_bytes: bytes, password: str = None, random_pos: bool = False):
    img = Image.open(image_path).convert('RGB')
    width, height = img.size
    max_capacity_bits = width * height * 3

    # Пакет данных: [4 байта общей длины] + [данные]
    full_data = len(data_bytes).to_bytes(4, 'big') + data_bytes
    total_bits_needed = len(full_data) * 8

    if total_bits_needed > max_capacity_bits:
        raise ValueError(
            f"Ошибка: Сообщение слишком большое. Требуется {total_bits_needed} бит, доступно {max_capacity_bits}.")

    bits = [(b >> i) & 1 for b in full_data for i in range(7, -1, -1)]

    flat_channels = []
    for p in img.getdata():
        flat_channels.extend(p)

    if random_pos:
        if not password:
            raise ValueError("Для псевдослучайного порядка необходим пароль.")
        pass_hash = hashlib.sha256(password.encode('utf-8')).digest()
        rng = random.Random(int.from_bytes(pass_hash, 'big'))
        indices = list(range(max_capacity_bits))
        rng.shuffle(indices)
        chosen_indices = indices[:len(bits)]

        for bit_idx, pos in enumerate(chosen_indices):
            flat_channels[pos] = (flat_channels[pos] & ~1) | bits[bit_idx]
    else:
        for idx, bit in enumerate(bits):
            flat_channels[idx] = (flat_channels[idx] & ~1) | bit

    new_pixels = [(flat_channels[i], flat_channels[i + 1], flat_channels[i + 2]) for i in
                  range(0, len(flat_channels), 3)]
    res_img = Image.new('RGB', (width, height))
    res_img.putdata(new_pixels)
    res_img.save(output_path, 'PNG')
    print(f"[Успех] Файл сохранен: {output_path}")


def extract_plain_data(stego_path: str) -> str:

    img = Image.open(stego_path).convert('RGB')
    flat_channels = []
    for p in img.getdata():
        flat_channels.extend(p)

    # Извлекаем все младшие биты
    bits = [c & 1 for c in flat_channels]

    # Читаем первые 32 бита (4 байта) — длина сообщения
    length_bits = bits[:32]
    msg_len = 0
    for b in length_bits:
        msg_len = (msg_len << 1) | b

    # Извлекаем биты самого сообщения
    msg_bits = bits[32: 32 + msg_len * 8]

    # Переводим биты обратно в байты
    msg_bytes = bytearray()
    for i in range(0, len(msg_bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | msg_bits[i + j]
        msg_bytes.append(byte)

    return msg_bytes.decode('utf-8')


# Статистический анализ
def run_statistical_analysis(cover_path, stego_paths, password):
    cover_arr = np.array(Image.open(cover_path).convert('RGB'), dtype=np.int16)
    max_cap = cover_arr.size

    variants = {"Cover": cover_arr}
    for name, path in stego_paths.items():
        variants[name] = np.array(Image.open(path).convert('RGB'), dtype=np.int16)

    print(
        f"\n{'Вариант':<25} | {'PSNR':<8} | {'SSIM':<8} | {'Changed(%)':<10} | {'P(LSB=1)':<10} | {'chi2':<10} | {'p-value':<10}")
    print("-" * 95)

    for name, arr in variants.items():
        if name == "Cover":
            lsbs = arr & 1
            p1 = np.sum(lsbs == 1) / lsbs.size
            flat = arr.flatten()
            chi2_vals = [((np.sum(flat == k) - (np.sum(flat == k) + np.sum(flat == k + 1)) / 2) ** 2) / (
                        (np.sum(flat == k) + np.sum(flat == k + 1)) / 2 + 1e-9) for k in range(0, 256, 2)]
            c_stat = sum(chi2_vals)
            p_val = 1 - chi2.cdf(c_stat, df=127)
            print(f"{name:<25} | {'-':<8} | {'-':<8} | {'-':<10} | {p1:<10.4f} | {c_stat:<10.2f} | {p_val:<10.4f}")
            continue

        psnr = compute_psnr(cover_arr, arr, data_range=255)
        ssim = compute_ssim(cover_arr, arr, channel_axis=2, data_range=255)
        diff_count = np.sum(cover_arr != arr)
        changed_ratio = (diff_count / max_cap) * 100

        lsbs = arr & 1
        p1 = np.sum(lsbs == 1) / lsbs.size

        flat = arr.flatten()
        chi2_vals = [((np.sum(flat == k) - (np.sum(flat == k) + np.sum(flat == k + 1)) / 2) ** 2) / (
                    (np.sum(flat == k) + np.sum(flat == k + 1)) / 2 + 1e-9) for k in range(0, 256, 2)]
        c_stat = sum(chi2_vals)
        p_val = 1 - chi2.cdf(c_stat, df=127)

        print(
            f"{name:<25} | {psnr:<8.2f} | {ssim:<8.4f} | {changed_ratio:<10.2f} | {p1:<10.4f} | {c_stat:<10.2f} | {p_val:<10.4f}")


if __name__ == "__main__":
    cover_img = "../imgs/akashi.png"
    pwd = "SecretLabPassword"
    msg = "Ералаша не забудем"

    # 1. Plain LSB
    plain_data = msg.encode('utf-8')
    embed_data(cover_img, "../imgs/stego_plain.png", plain_data, random_pos=False)

    # 2. Encrypted LSB
    salt, nonce, ciphertext = encrypt_message(pwd, msg)
    enc_payload = salt + nonce + len(ciphertext).to_bytes(4, 'big') + ciphertext
    embed_data(cover_img, "../imgs/stego_encrypted.png", enc_payload, random_pos=False)

    # 3. Encrypted Random LSB
    embed_data(cover_img, "../imgs/stego_random.png", enc_payload, password=pwd, random_pos=True)

    #Проверка извлечения и полного совпадения
    extracted_msg = extract_plain_data("../imgs/stego_plain.png")
    print(f"\n[Извлеченный текст из Plain LSB]: {extracted_msg}")

    assert msg == extracted_msg, "Ошибочка: Извлеченный текст не совпадает с исходным"
    print("[Ура]: Исходное и извлеченное сообщения совпали\n")

    # Запуск статистического сравнения (
    stego_dict = {
        "Plain LSB": "../imgs/stego_plain.png",
        "Encrypted LSB": "../imgs/stego_encrypted.png",
        "Encrypted Random LSB": "../imgs/stego_random.png"
    }
    run_statistical_analysis(cover_img, stego_dict, pwd)