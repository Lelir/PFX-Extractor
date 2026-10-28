# PFX Extractor

Application Windows qui extrait le certificat et la clé privée d’un fichier PFX/P12 à l’aide d’OpenSSL.

## Prérequis

- Windows 64 bits.
- Rust et Cargo installés via [rustup](https://rustup.rs/), avec les outils de compilation C++ Microsoft (Visual Studio Build Tools, charge de travail « Développement Desktop en C++ »).
- OpenSSL installé à `C:\Program Files\OpenSSL-Win64\bin\openssl.exe`. Si nécessaire, adapte la constante `OPENSSL_PATH` dans `src/main.rs`. OpenSSL est aussi nécessaire sur le poste où l’application sera exécutée.

## Compiler et lancer

Dans PowerShell, à la racine du projet :

```powershell
cargo run
```

Pour compiler une version optimisée :

```powershell
cargo build --release
```

Le programme est créé dans `target\release\pfx-extractor.exe`. La première compilation télécharge les dépendances et peut prendre plusieurs minutes.

## Utilisation

Glisse un fichier `.pfx` ou `.p12` dans la fenêtre, saisis son mot de passe et clique sur **Extraire le certificat et la clé privée**. Les fichiers sont créés dans un dossier `<nom>_extracted` à côté du fichier source. L’application demande confirmation avant d’écraser des fichiers existants.


## Auteur

Développé par Tobias Rouiller.