import ssl
import socket
import hashlib
from OpenSSL import crypto


def get_certificate_hash(hostname, port=443):
    # Створюємо TLS-з'єднання
    context = ssl.create_default_context()

    # Підключаємося до сервера
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Отримуємо сертифікат
            cert = ssock.getpeercert(True)  # Отримуємо сертифікат у бінарному вигляді

            # Завантажуємо сертифікат з OpenSSL
            cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

            # Отримуємо публічний ключ сертифіката
            public_key = cert_obj.get_pubkey()

            # Отримуємо хеш публічного ключа (SHA256)
            public_key_hash = hashlib.sha256(crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)).hexdigest()

            # Отримуємо термін дії сертифіката
            not_after = cert_obj.get_notAfter().decode("utf-8")
            not_before = cert_obj.get_notBefore().decode("utf-8")

            # Повертаємо хеш публічного ключа та терміни дії
            return public_key_hash, not_before, not_after


def main():
    while True:
        # Введіть домен або IP-адресу для підключення
        hostname = input("Введіть ім'я хоста або IP-адресу сервера (або 'exit' для виходу): ")

        if hostname.lower() == 'exit':
            print("Вихід з програми...")
            break

        try:
            cert_hash, not_before, not_after = get_certificate_hash(hostname)
            print(f"Хеш публічного ключа SSL-сертифіката: {cert_hash}")
            print(f"Термін дії сертифіката: {not_before} - {not_after}")
        except Exception as e:
            print(f"Помилка: {e}")


if __name__ == "__main__":
    main()
