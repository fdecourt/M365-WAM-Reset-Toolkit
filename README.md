# M365 WAM Reset Toolkit (V8)

Advanced Microsoft 365 token reset and WAM cleanup tool for Windows 10/11.

---

## 🧭 Description

This script allows you to:

- Fully reset Microsoft 365 authentication tokens.
- Clean WAM (Web Account Manager) profiles.
- Reset AzureAD, Workplace Join and Microsoft Account (MSA) sessions.
- Purge Credential Manager saved credentials.
- Reset OneDrive configuration.
- Schedule locked files and directories deletion after reboot (via PendingFileRenameOperations).
- Safely handle locked files during running Office, OneDrive or AzureAD sessions.
- Fully compatible with dual personal & professional Microsoft accounts.

---


## ⚙ Requirements

- Windows 10 or 11 (x64).
- Local admin rights (script must be executed as Administrator).
- A reboot is required after execution to finalize the locked files deletion.

---

## 🚀 How to use

1️⃣ Launch `M365_TOKEN_RESET_V8.ps1` in an elevated PowerShell (Administrator mode).

2️⃣ Let the full reset run until completion.

3️⃣ Reboot the machine to apply all planned deletions.

4️⃣ Reconnect your Microsoft 365 personal and/or professional accounts as needed.

---

## 🔧 Key features

- Fully transactional cleanup of WAM folders.
- Handles locked files via proper reboot scheduling.
- Fully automated — zero manual interaction required.
- Compatible with hybrid identity environments (MSA + AzureAD + Workplace Join + Entra).
- Preserves user profiles and user data.
- Compatible with coexistence of personal & professional M365 accounts.

---

## 🚫 Limitations

- This script does not delete user data or profiles.
- Some Intune-managed hybrid devices may require additional permissions.
- PowerShell Desktop Edition required (default on Windows 10/11).

---

## ⚠ Disclaimer

This script is provided **as is**, without any warranty of any kind.  
Use it at your own risk.  
The author cannot be held responsible for any consequences resulting from its use.

## 📄 License

This project is licensed under the **Creative Commons Attribution 4.0 International (CC BY 4.0)** license.

- You are free to use, modify, share, and redistribute this script, even commercially.
- You must give appropriate credit to the original author: **fdecourt**.
- Full license text: https://creativecommons.org/licenses/by/4.0/
---

## 👨‍💻 Author

Originally written and field-tested by fdecourt

---

# 🇫🇷 **VERSION FRANÇAISE**

---

# M365 WAM Reset Toolkit (V8)

Outil avancé de réinitialisation des jetons Microsoft 365 et de nettoyage complet de WAM pour Windows 10/11.

---

## 🧭 Description

Ce script permet de :

- Réinitialiser complètement les jetons d’authentification Microsoft 365.
- Purger les profils WAM (Web Account Manager).
- Réinitialiser les sessions AzureAD, Workplace Join et comptes personnels Microsoft (MSA).
- Vider les identifiants enregistrés dans le Credential Manager.
- Réinitialiser la configuration de OneDrive.
- Planifier la suppression des fichiers verrouillés au redémarrage (via PendingFileRenameOperations).
- Gérer proprement les fichiers verrouillés même lorsque Office, OneDrive ou AzureAD sont encore actifs.
- Compatible avec la coexistence de comptes professionnels et personnels Microsoft 365.

---


## ⚙ Pré-requis

- Windows 10 ou 11 (x64).
- Droits administrateur local (exécution en tant qu’administrateur).
- Un redémarrage est requis après exécution pour finaliser la suppression des fichiers verrouillés.

---

## 🚀 Utilisation

1️⃣ Exécuter `M365_TOKEN_RESET_V8.ps1` via PowerShell en mode administrateur.

2️⃣ Laisser le script s’exécuter jusqu’au bout.

3️⃣ Redémarrer la machine pour appliquer toutes les suppressions planifiées.

4️⃣ Reconnecter les comptes professionnels et personnels selon les besoins.

---

## 🔧 Fonctionnalités clés

- Nettoyage transactionnel complet des dossiers WAM.
- Gestion différée des fichiers verrouillés via planification de reboot.
- 100% automatisé, aucune interaction manuelle nécessaire.
- Compatible avec les environnements hybrides (MSA + AzureAD + Workplace Join + Entra).
- Ne supprime pas les profils utilisateurs ni les données locales.
- Supporte la coexistence de comptes M365 personnels et professionnels.

---

## 🚫 Limitations

- Ne supprime aucune donnée personnelle ni profil utilisateur.
- Certains postes fortement gérés par Intune peuvent nécessiter des droits supplémentaires.
- Fonctionne uniquement sous Windows PowerShell Desktop (par défaut sur Windows 10/11).

---

## ⚠ Avertissement

Ce script est fourni **tel quel**, sans aucune garantie d'aucune sorte.  
Son utilisation est sous la responsabilité exclusive de l'utilisateur.  
L'auteur ne pourra être tenu responsable de toute conséquence liée à son utilisation.

## 📄 Licence

Ce projet est sous licence **Creative Commons Attribution 4.0 International (CC BY 4.0)**.

- Vous êtes libre d'utiliser, modifier, partager et redistribuer ce script, même à des fins commerciales.
- Vous devez créditer l'auteur original : **fdecourt**.
- Texte complet de la licence : https://creativecommons.org/licenses/by/4.0/

---

## 👨‍💻 Auteur

Écrit et validé sur le terrain par fdecourt
