# Gestionnaire de Mots de Passe

Un gestionnaire de mots de passe sécurisé et modulaire écrit en **Rust**. Le projet est structuré sous forme de workspace Cargo séparant le cœur logique, l'interface en ligne de commande (CLI) et l'interface graphique (GUI).

---

## 📁 Structure du Projet

Le projet est divisé en plusieurs modules complémentaires :

```text
.
├── gestionnaire_core/            # Cœur logique (Bibliothèque)
│   ├── Cargo.toml                # Dépendances du module core
│   └── src/
│       ├── lib.rs                # Déclarations et point d'entrée de la bibliothèque
│       ├── chiffrement.rs        # Algorithmes de chiffrement / déchiffrement
│       ├── gestionnaire_cle.rs   # Génération et dérivation des clés de sécurité
│       ├── salt.rs               # Gestion du grain de sel (salt) pour le hachage
│       ├── chaine_securisee.rs   # Structure mémoire sécurisée (nettoyage automatique)
│       └── utilitaires.rs        # Fonctions auxiliaires et gestion des E/S
├── gestionnaire_cli/     	  # Interface en ligne de commande (CLI)
├── gestionnaire_gui/     	  # Interface graphique (GUI)
├── gestionnaire/ 		  # Dossier de données utilisateur (fichiers chiffrés et sauvegardes)
│   ├── MDP           		  # Fichier principal des coffres/mots de passe
│   └── sauvegardes/ 		  # Sauvegardes automatiques et manuelles (.bak)
├── Cargo.toml                    # Configuration du Workspace Rust
└── Cargo.lock        		  # Verrouillage des dépendances
```

### Modules

* **`gestionnaire_core`** : Implémente la logique métier (chiffrement, gestion du salt, nettoyage mémoire avec `chaine_securisee`, utilitaires).
* **`gestionnaire_cli`** : Application terminal pour interagir rapidement avec le coffre-fort.
* **`gestionnaire_gui`** : Application graphique pour une gestion visuelle des identifiants.
* **`gestionnaire/sauvegardes/`** : Système de rotation et d'archivage automatique ou manuel des bases de données de mots de passe.

---

## Prérequis

* **Rust** et **Cargo**
---

## Compilation et Exécution

### 1. Interface en ligne de commande (CLI)
Pour lancer la version terminal :
```bash
cargo run -p gestionnaire_cli
```

### 2. Interface Graphique (GUI)
Pour lancer la version graphique :
```bash
cargo run -p gestionnaire_gui
```

### 3. Compilation
Pour générer les binaires optimisés :
```bash
cargo build --release
```
Les exécutables se trouveront dans le dossier `target/release/`.

---

## Sauvegardes et Sécurité

* **Fichiers de données** : Les mots de passe sont stockés de manière chiffrée.
* **Sauvegardes `.bak`** : Des snapshots automatiques (`sauvegarde_automatique_X.bak`) et manuels (`sauvegarde_manuelle_X.bak`) sont générés dans le dossier `gestionnaire/sauvegardes/` afin de prévenir toute perte de données.