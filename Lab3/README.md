# SRP - Lab 3: Hash funkcije

U ovoj vježbi student će se upoznati sa radom *hash* funkcija kao i radom 'sporih' funkcija za generiranje simetričnih ključeva.

## Uvod

U prvom dijelu vježbe zadatak studenta je saznati nasumično generirani broj koji je pohranjen u direktoriju [challenges](challenges).

Zadatak studenta je saznati nasumično generirani broj pohranjen u obliku *hash* vrijednosti. Kao *hash* algoritam je korišten SHA-256; student ne treba poznavati detalja rada *hash* algoritma za uspješno rješavanje zadatka.

## Zadatak 1.

Za svakog studenta je kreirana datoteka u direktoriju [challenges](challenges) koja sadrži nasumično generirani broj pohranjen u obliku *hash* vrijednosti. Datoteke imaju ekstenziju `.hash` dok je ime datoteke kao i u prethodnoj vježbi generirano primjenom kriptografske *hash* funkcije SHA-256 na vrijednostima `(<Prezime><Ime> + <SALT>)`, gdje je `<SALT>` vrijednost koju će vam profesori dati na vježbama.

### Postupak *hashiranja*

Za potrebe ove vježbe, u skripti `hash_lab3.py` je definirana funkcija `hash_me` koja uzima prethodno nasumično generirani broj (`passcode`) i *hash* algoritam (`hashes.SHA256()`).

```python
challenge = str(int.from_bytes(urandom(3), byteorder='big') & 0x2FFFFF)
passcode = challenge.encode()
hash_value = hash_me(passcode, hashes.SHA256())
```

### Vaš zadatak

Vaš zadatak jer razumijeti kod za *hash*-iranje koji je dan u nastavku, te kreirati novu skriptu koja će saznati nasumično generirani broj koji se nalazi u odgovarajućoj datoteci u direktoriju [challenges](challenges). U osnovi trebate kreirati funkciju koja će primjenom *brute-force* napada saznati nasumično generirani broj.

```python
# file hash_lab3.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from os import path
from os import urandom
import base64


STUDENTNAME = "PerkovicToni" # ne koriste se HR slova (čćžšđ)
SALT = "!ASK_PROFESSOR!" # pitajte profesora na vježbama


# Generate hash
def hash_me(msg, hash_function):
    digest = hashes.Hash(hash_function, backend=default_backend())
    if not isinstance(msg, bytes):
        msg = msg.encode()
    digest.update(msg)
    return digest.finalize()


if __name__ =='__main__':

    # Generate challenge
    challenge = str(int.from_bytes(urandom(3), byteorder='big') & 0x2FFFFF)
    passcode = challenge.encode()
    hash_value = hash_me(passcode, hashes.SHA256())

    # Save hash challenge to file
    passcode_file_name = hash_me(str.encode(STUDENTNAME + SALT), hashes.SHA256()).hex() + '.hash'
    with open(passcode_file_name, 'wb') as f:
        content_to_write = base64.b64encode(hash_value)
        f.write(content_to_write)
```

## Zadatak 2.

U drugom dijelu vježbe zadatak studenta je saznati ključ te dešifrirati *ciphertext* dobiven enkripcijom odgovarajućeg *plaintext*-a. Za enkripciju je korištena AES šifra/enkripcijski algoritam u tzv. CTR enkripcijskom modu. U ovoj laboratorijskoj vježbi korištena je spora *Scrypt* funkcija za generiranje potrebnih simetričnih ključeva iz nasumično generiranog broja.

### Postupak enkripcije *plaintext*-a (vašeg izazova)

Za enkripciju *plaintext*-ova kreirana je jednostavna python skripta/modul `encrypt_lab3.py`. Za potrebe ove vježbe, u skripti `encrypt_lab3.py` definirana je funkcija `encrypt_CTR` koja uzima 128 bitni inicijalizacijski vektor (`iv`), odgovarajući *plaintext* (`CHALLENGE`) te ga šifrira/enkriptira tajnim 256 bitnim ključem (`key`) i vraća odgovarajući *ciphertext*. Ključ je izveden iz nasumično generiranog broja (passcode) korištenjem spore *Scrypt* funkcije.

```python
# Generate passcode
passcode = str(int.from_bytes(urandom(2), byteorder='big') & 0x0FFF)
passcode = passcode.encode()

# Generate key
KDF = Scrypt(
    length=32,
    salt=b'salt',
    n=2**15,
    r=8,
    p=1,
    backend=default_backend()
)
key = KDF.derive(passcode)

iv = urandom(16)
ciphertext = encrypt_CTR(key, iv, CHALLENGE)
```

Navedena skripta potom pohranjuje dobiveni *ciphertext* i inicijalizacijski vektor u odgovarajuću datoteku.

```python
challenge_file_name = hash_me(str.encode(STUDENTNAME + SALT), hashes.SHA256()).hex() + '.enc'
with open(challenge_file_name, 'wb') as f:
    content_to_write = base64.b64encode(iv + ciphertext)
    f.write(content_to_write)
```


### Vaš zadatak

Za svakog studenta kreirana je datoteka u direktoriju [slow_challenges](slow_challenges) koja sadrži šifrirani `plaintext`. Datoteke imaju ekstenziju `.enc` a ime datoteke generirano je primjenom kriptografske hash funkcije SHA-256.

Vaš zadatak je razumijeti kod za šifriranje/enkripciju koji je dan u nastavku, te kreirati novu skriptu koja će dešifrirati/dekriptirati *ciphertext* koji se nalazi u odgovarajućoj datoteci u direktoriju [slow_challenges](slow_challenges). Koristeći činjenicu da je za generiranje ključa korišten nasumično generirani broj, student može jednostavno testirati potencijalne ključeve te pokušati dekriptirati šifrirani plaintext.

```python
# file encrypt_lab3.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend
from os import path
from os import urandom
import base64


STUDENTNAME = "PerkovicToni" # ne koriste se HR slova (čćžšđ)
SALT = "!ASK_PROFESSOR!" # pitajte profesora na vježbama

CHALLENGE = "Chuck Norris je vodu iz pipe popio na eks!"


# Generate hash
def hash_me(msg, hash_function):
    digest = hashes.Hash(hash_function, backend=default_backend())
    if not isinstance(msg, bytes):
        msg = msg.encode()
    digest.update(msg)
    return digest.finalize()


def encrypt_CTR(key, iv, plaintext, cipher=algorithms.AES):
    if not isinstance(key, bytes):
        key = key.encode()
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode()

    encryptor = Cipher(cipher(key), modes.CTR(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext)
    ciphertext += encryptor.finalize()

    return ciphertext


def decrypt_CTR(key, iv, ciphertext, cipher=algorithms.AES):
    if not isinstance(key, bytes):
        key = key.encode()

    decryptor = Cipher(cipher(key), modes.CTR(iv), backend=default_backend()).decryptor()
    plaintext = decryptor.update(ciphertext)
    plaintext += decryptor.finalize()

    return plaintext


if __name__ =='__main__':

    # Generate passcode
    passcode = str(int.from_bytes(urandom(2), byteorder='big') & 0x0FFF)
    passcode = passcode.encode()

    # Generate key
    KDF = Scrypt(
        length=32,
        salt=b'salt',
        n=2**15,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = KDF.derive(passcode)

    iv = urandom(16)
    ciphertext = encrypt_CTR(key, iv, CHALLENGE)

    challenge_file_name = hash_me(str.encode(STUDENTNAME + SALT), hashes.SHA256()).hex() + '.enc'
    with open(challenge_file_name, 'wb') as f:
        content_to_write = base64.b64encode(iv + ciphertext)
        f.write(content_to_write)
```
