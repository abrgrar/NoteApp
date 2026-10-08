"""Compare AES-ECB and AES-GCM using the image beside this script."""

import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_ecb(data, key):
    # AES uses 16-byte blocks; PKCS7 adds the required padding.
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_ecb(ciphertext, key):
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def encrypt_gcm(data, key):
    # Generate a fresh nonce for every encryption with this key.
    nonce = os.urandom(12)
    # AESGCM appends a 16-byte authentication tag to the ciphertext.
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce, ciphertext


def decrypt_gcm(ciphertext, key, nonce):
    # Decryption also verifies the authentication tag.
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def save_comparison(original, ecb_image, gcm_image, output_path):
    margin = 16
    title_height = 40
    width, height = original.size
    comparison = Image.new(
        'RGB',
        (width * 3 + margin * 4, height + title_height + margin * 2),
        'white',
    )
    draw = ImageDraw.Draw(comparison)
    font = ImageFont.load_default(size=20)
    for index, (title, image) in enumerate([
        ('Original', original),
        ('AES-ECB', ecb_image),
        ('AES-GCM', gcm_image),
    ]):
        x = margin + index * (width + margin)
        draw.text((x, margin), title, fill='black', font=font)
        comparison.paste(image, (x, margin + title_height))
    comparison.save(output_path)


if __name__ == '__main__':
    folder = Path(__file__).resolve().parent
    image_path = folder / 'ants_16.png'
    output_folder = folder / 'aes_output'
    output_folder.mkdir(exist_ok=True)

    with Image.open(image_path) as source:
        original_size = source.size
        # Composite transparency onto white before encrypting all RGB pixels.
        rgba = source.convert('RGBA')
        background = Image.new('RGBA', rgba.size, 'white')
        background.alpha_composite(rgba)
        image = background.convert('RGB')

    # Enlarge small pixel art BEFORE encryption to expose repeated ECB blocks.
    scale = max(1, (256 + max(image.size) - 1) // max(image.size))
    if scale > 1:
        image = image.resize(
            (image.width * scale, image.height * scale),
            Image.Resampling.NEAREST,
        )

    # Encrypt raw pixels, rather than the PNG header and compressed file data.
    data = image.tobytes()
    key = AESGCM.generate_key(bit_length=256)

    ecb_ciphertext = encrypt_ecb(data, key)
    nonce, gcm_ciphertext = encrypt_gcm(data, key)

    # These PNGs visualize ciphertext only. Keep the full encrypted bytes above
    # for decryption: ECB includes padding, and GCM includes its tag.
    ecb_image = Image.frombytes('RGB', image.size, ecb_ciphertext[:len(data)])
    gcm_image = Image.frombytes('RGB', image.size, gcm_ciphertext[:-16])

    ecb_plaintext = decrypt_ecb(ecb_ciphertext, key)
    gcm_plaintext = decrypt_gcm(gcm_ciphertext, key, nonce)
    assert ecb_plaintext == data, 'ECB did not restore the original pixels.'
    assert gcm_plaintext == data, 'GCM did not restore the original pixels.'

    ecb_decrypted = Image.frombytes('RGB', image.size, ecb_plaintext)
    gcm_decrypted = Image.frombytes('RGB', image.size, gcm_plaintext)
    for filename, result in [
        ('original.png', image),
        ('ecb_encrypted.png', ecb_image),
        ('gcm_encrypted.png', gcm_image),
        ('ecb_decrypted.png', ecb_decrypted),
        ('gcm_decrypted.png', gcm_decrypted),
    ]:
        result.save(output_folder / filename)

    save_comparison(image, ecb_image, gcm_image, output_folder / 'comparison.png')

    # Changing one ciphertext byte must cause GCM authentication to fail.
    tampered = bytearray(gcm_ciphertext)
    tampered[0] ^= 1
    try:
        decrypt_gcm(bytes(tampered), key, nonce)
    except InvalidTag:
        print('GCM correctly rejected the modified ciphertext.')
    else:
        raise AssertionError('GCM accepted modified ciphertext.')

    print(f'Input: {image_path.name} ({original_size[0]} x {original_size[1]})')
    print(f'Experiment image: {image.width} x {image.height}')
    print('ECB and GCM both restored the original pixels. All tests passed.')
    print(f'Comparison saved to: {output_folder / "comparison.png"}')
