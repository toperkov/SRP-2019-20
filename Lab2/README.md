# SRP - Lab 2: Symmetric crypto challenge

U sklopu vježbe student će riješiti jednostavan _crypto_ izazov. Student će pri tome koristiti _python_ programski jezik. Kroz ovu vježbu student će se upoznati s osnovama **simetrične kriptografije**.

## Uvod

Zadatak studenta je dešifrirati dani _ciphertext_ dobiven enkripcijom odgovarajućeg _plaintext_-a. Za enkripciju je korištena AES šifra/enkripcijski algoritam u tzv. CBC enkripcijskom modu; student ne treba poznavati detalje AES algoritma ni CBC moda za uspješno rješavanje zadatka.

Za svakog studenta kreirana je datoteka u direktoriju [Studenti](Studenti) koja sadrži šifrirani _plaintext_. Datoteke imaju ekstenziju `.enc` a ime datoteke generirano je primjenom kriptografske _hash_ funkcije SHA-256 kako je prikazano u nastavku:

```python
hash("PerkovicToni" + <SALT>) = f3f496e59923ea2f120edbe0b603fac4719bb01e250e9534e401af6f1edb0a5e
```

gdje je `<SALT>` vrijednost koju će vam profesori dati na vježbama.

> **NAPOMENA:**  
> Ime studenta formatirano je kao: `<Prezime><Ime>`. Primjetite kako nema razmaka između prezimena i imena, te da nisu korištena dijakritička slova (čćžšđ).

> **ZAŠTO NAVEDENA KOMPLIKACIJA?**  
> Nastojali smo osigurati anonimnost studentata, odnosno izbjeći objavljivanje stvarnih imena na javnom/otvorenom forumu.

Ime vlastite datoteke možete saznati izvršavanjem sljedećeg koda u `python shell`-u:

```python
>>> from cryptography.hazmat.primitives import hashes
>>> from cryptography.hazmat.backends import default_backend
>>> imeStudenta = <PrezimeIme> + <SALT> # NAPOMENA: SALT dobivate od profesora
>>> digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
>>> digest.update(str.encode(imeStudenta))
>>> filename = digest.finalize().hex()
>>> print(filename)
```

## Postupak enkripcije _plaintext_-a (vašeg izazova)

Za enkripciju _plaintext_-ova kreirana je jednostavna python skripta/modul `encrypt_lab2.py`. U skripti koristimo modul [cryptography](https://cryptography.io), s kojim smo se upoznali u prethodnoj vježbi. Za potrebe ove vježbe, u skripti `encrypt_lab2.py` definirana je funkcija `encrypt` koja uzima 128 bitni inicijalizacijski vektor (`iv`), odgovarajući _plaintext_ (`QUOTE`) te ga šifrira/enkriptira tajnim 256 bitnim ključem i vraća odgovarajući ciphertext (`enc`).

```python
key = os.urandom(KEY_BLOCK_SIZE)
iv = os.urandom(IV_BLOCK_SIZE)
enc = encrypt(key, iv, str.encode(QUOTE))
```

Navedena skripta potom pohranjuje dobiveni _ciphertext_, enkripcijski ključ, inicijalizacijski vektor u odgovarajuću datoteku.

```python
f_out = open(filename + ".enc", 'wb')
content_to_write = base64.b64encode(key + enc + iv)
f_out.write(content_to_write)
f_out.close()
```

Kao što smo već opisali, za svakog studenta kreirana je posebna datoteka. Cijela skripta prikazana je u nastavku.

## Vaš zadatak

Vaš zadatak je razumijeti kod za šifriranje/enkripciju koji je dan u nastavku, te kreirati novu skriptu koja će dešifrirati/dekriptirati _ciphertext_ koji se nalazi u odgovarajućoj datoteci u direktoriju [Studenti](Studenti). U osnovi trebate kreirati funkciju `decrypt` koja će invertirati postupak enkripcije (inverzna funkcija funkcije `encrypt`).

> **VAŽNO:**  
> Za potrebe rada s kriptografskim primitivima (enkripcijskim algoritmima te kriptografskim hash funkcijama) koristili smo Python modul [cryptography](https://cryptography.io). Na web stranicama modula dana su detaljna objašnjenja korištenja kriptografskih primitiva sa primjerima (receptima).

> **U SLUČAJU PANIKE:**  
> Na prvi pogled zadatak može izgledati _zastrašujuće_. Razlozi su višestruki: većini studentata ovo je prvi put da su izloženi problematici iz područja informacijske sigurnosti, na nastavi nismo niti ćemo pokriti sve detalje simetričnih kriptosustava, dio studenata prvi put koristi `python` ili nema previše iskustva s programiranjem, i dr. U osnovi, panici nema mjesta, tu su profesori koji će pokušati odgovoriti na sva vaša pitanja i voditi vas kroz zadatak.  
> Ideja zadatka je usvojiti osnovnu terminologiju simetričnih kriptosustava kroz praktičan rad.

```python
# file encrypt_lab2.py

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives import (
    hashes,
    padding
)
from cryptography.hazmat.backends import default_backend
import os
import base64


KEY_BLOCK_SIZE = 32
CIPHER_BLOCK_LENGTH = 128
IV_BLOCK_SIZE = 16
CIPHER = algorithms.AES

STUDENTNAME = "PerkovicToni" # ne koriste se HR slova (čćžšđ)
SALT = "!ASK_PROFESSOR!" # pitajte profesora na vježbama

QUOTE = "The lock on the old door could only take short keys"


def encrypt(key, iv, plaintext):
    ''' Function encrypt '''

    padder = padding.PKCS7(CIPHER_BLOCK_LENGTH).padder()
    padded_plaintext = padder.update(plaintext)
    padded_plaintext += padder.finalize()

    cipher = Cipher(CIPHER(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext)
    ciphertext += encryptor.finalize()

    return ciphertext


if __name__ =='__main__':

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str.encode(STUDENTNAME + SALT))
    filename = digest.finalize().hex()

    key = os.urandom(KEY_BLOCK_SIZE)
    iv = os.urandom(IV_BLOCK_SIZE)
    enc = encrypt(key, iv, str.encode(QUOTE))

    f_out = open(filename + ".enc", 'wb')
    content_to_write = base64.b64encode(iv + enc + key)
    f_out.write(content_to_write)
    f_out.close()
```
