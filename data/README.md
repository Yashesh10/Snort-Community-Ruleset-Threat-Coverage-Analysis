# MITRE ATT&CK Dataset

`enterprise-attack.json` is the official Enterprise ATT&CK STIX 2.1 bundle
downloaded from:

https://github.com/mitre-attack/attack-stix-data

At integration time, the bundle identified itself as Enterprise ATT&CK v19.1,
modified May 12, 2026.

Refresh it from the official repository:

```powershell
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" `
  -OutFile ".\data\enterprise-attack.json"
```

MITRE ATT&CK is provided subject to MITRE's ATT&CK Terms of Use.
