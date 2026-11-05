# Fixtures Windows PowerShell 5.1 / PraRemoteMailbox 2.2.0

Fichiers **reellement produits** par le code de production 2.2.0 sous Windows PowerShell 5.1, figes pour prouver que le
moteur migre (PowerShell 7.5+) relit et restaure toujours les sauvegardes, preuves et paquets Finalize des versions 2.x,
au bit pres. Donnees 100 % synthetiques (contoso.com, SIDs fictifs). Ne jamais regenerer pour "faire passer" un test :
si un test echoue sur ces fichiers, c'est le moteur qui est en tort.

## Provenance

| Element | Valeur |
|---------|--------|
| Version du code | 2.2.0 (`main` apres la PR #7) |
| Commit source | `82dfe37061c79df7977bee51af52c9c793f01e06` |
| Moteur | Windows PowerShell 5.1.26100.9711 (Desktop), CLR 4.0.30319.42000 |
| Genere par | `tools/New-LegacyFixtures.ps1` (hors paquet) |
| Genere le | 2026-11-04 (UTC) |
| Taille | 1114 Ko en 39 fichiers (hors README.md, sets.json, fixtures.sha256) |

Commande :

```
git worktree add <scratch>/pra-2.2.0 82dfe37061c79df7977bee51af52c9c793f01e06
powershell.exe -NoProfile -File tools/New-LegacyFixtures.ps1 -SourceRoot <scratch>/pra-2.2.0 -WorkRoot C:\PraFx -Force
```

Les identifiants de lot (`Batch-<guid>`), RunId et horodatages sont produits par le code de production a chaque
execution : une regeneration donne d'autres noms et d'autres empreintes. La copie commitee fait foi ; `fixtures.sha256`
liste le SHA-256 de chaque fichier (`sha256sum -c` ou `Get-FileHash`). `.gitattributes` interdit toute
normalisation de fin de ligne.

## Jeux

| Jeu | Contenu | Produit par |
|-----|---------|-------------|
| `01-convert-users` | Lot Convert schema 3 de 2 utilisateurs : `Convert-*.json`, `.json.sha256`, `.clixml` (codec `PraDataOnlyClixml-v1`), `Journal-*.jsonl`, preuve `State-*.json` (+ `.sha256`, `ADVerified`) | `Invoke-PraAdBatch` / `Save-PraBatch` (PRA.Directory + PRA.Backup) |
| `02-recover-users` | Lot Recover schema 3 issu de 01, avec son journal et sa preuve `State-*.json` | `Invoke-PraRemoteMailbox.ps1 -Action Recover -Phase AD` (processus `powershell.exe` enfant) |
| `03-finalize-shared13` | Paquet `Finalize-<guid>/` : manifeste `RecoverFinalize` schema 2 (+ `.sha256`), copies des lots Convert et Recover (JSON, `.sha256`, `.clixml`), preuve `State`, et dossier `<RunId>-cloud` (journal cloud) | `Invoke-PraRemoteMailbox.ps1 -Action Recover -Phase Cloud` (cas `CloudConfirmed13`, `Save-PraFinalizePackage`) |
| `04-shared13` | Lots Convert et Recover de 13 boites partagees (`nTSecurityDescriptor` et `msExchMailboxSecurityDescriptor` natifs : `ActiveDirectorySecurity` 100 ACE + 1 refus + SID, `MultiString`, `Bytes`; permissions FullAccess/SendAs/SendOnBehalf). Pour tenir le budget de taille, les JSON/`.sha256`/`.clixml` de ces deux lots ne sont stockes qu'une fois, dans le paquet Finalize du jeu 03 (copies octet-identiques, verifiees a la generation) ; 04 conserve leurs journaux et preuves `State-*.json` | idem 01/02 |
| `05-legacy/schema1`, `schema2` | `historical.clixml` (`PSSerializer` 5.1 de 2 objets aux noms de types natifs `ADUser`/`ADAccount`/`ADPrincipal`/`ADObject`, bloc `<Props>`, `ObjectGUID` en `<G>`) + `historical.json` schema 1 (`AddedToLicenseGroup`) et schema 2 (`.sha256`, `RawFile`, `RawHash`) | emulation : 2.2.0 n'ecrit plus ces schemas (voir ci-dessous) |
| `06-all-types` | `all-types.clixml` : un objet portant tous les scalaires, collections, binaires et descripteurs de securite natifs du codec (test `OOM` 1163). Entree : `New-PraAllTypesUser.ps1` (source unique, relue par le test pour comparer **octet a octet** la sortie du codec courant) | `ConvertTo-PraRawSnapshot` + `Write-PraRawCapture` |

`sets.json` indexe les fichiers (role, schema, operation, nombre d'enregistrements) pour les tests.
Dependances entre jeux : 02 prouve contre la source 01 ; les fichiers des lots Convert et Recover de 04 sont ceux du paquet 03 (stockes une seule fois).

## Verification

```
# lecture par le code de production 2.2.0 sous Windows PowerShell 5.1 (doit passer)
powershell.exe -NoProfile -Command "$env:PRA_FX_REPO='<checkout>'; Invoke-Pester tests/PraLegacyFixtures.Tests.ps1"
# meme fichier sous pwsh avec le moteur migre (PRA_FX_REPO absent : le depot courant)
pwsh -NoProfile -Command "Invoke-Pester tests/PraLegacyFixtures.Tests.ps1"
```

Le test est neutre vis-a-vis de l'edition ; il relit chaque jeu par les lecteurs de production (`Import-PraBackup`,
`Test-PraRawCapture`, `Import-PraProof`, `Get-PraFinalizeInput`), compare l'octet-a-octet du codec (06) et verifie
qu'un octet inverse est refuse.
## Ecarts connus par rapport a une sauvegarde 2.2.0 "de terrain"

- Schemas 1 et 2 : emulation (le code 2.2.0 ne sait plus les ecrire). Les enregistrements viennent de `New-PraPlan`
  (production) ; le CLIXML historique est un vrai `PSSerializer` 5.1 d'objets CLR synthetiques portant les noms de types
  natifs, pas la sortie d'un `Get-ADUser` reel (aucun annuaire disponible).
- Le serveur d'annuaire, les groupes et les utilisateurs sont ceux du harnais synthetique des tests (`contoso.com`) ;
  le cloud est la barriere synthetique des tests (aucune connexion).
- Les sauvegardes du labo reel (valeurs AD reelles) ne se committent pas : elles servent a la revalidation en labo.