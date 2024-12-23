# MoudyHunter

## Description
### Français
**MoudyHunter** est un outil d'analyse de vulnérabilités web développé par **Moudy Solutions**. Il permet de détecter des failles de sécurité courantes telles que :
- **Injection SQL**
- **Cross-Site Scripting (XSS)**
- **Liste de répertoires sensibles**

MoudyHunter automatise également l'exploration de liens à partir de pages cibles et effectue des tests sur les URL identifiées.

### English
**MoudyHunter** is a web vulnerability analysis tool developed by **Moudy Solutions**. It helps detect common security flaws such as:
- **SQL Injection**
- **Cross-Site Scripting (XSS)**
- **Sensitive Directory Listings**

MoudyHunter also automates link crawling from target pages and performs tests on identified URLs.

---

## Fonctionnalités / Features
- Analyse des liens pour détecter les paramètres et segments exploitables.  
  Analyzes links to detect exploitable parameters and segments.  
- Détection des vulnérabilités suivantes :  
  Detects the following vulnerabilities:  
  - Injection SQL / SQL Injection  
  - XSS / XSS  
  - Répertoires sensibles comme `.git`, `.env`, `backup`, etc.  
    Sensitive directories like `.git`, `.env`, `backup`, etc.  
- Génération d'un rapport de vulnérabilités détaillé.  
  Generates a detailed vulnerability report.  
- Interface utilisateur simple via terminal.  
  Simple user interface via terminal.  

---

## Installation

### Français
#### Prérequis
- **Python 3.7+**
- Les bibliothèques suivantes :
  - `requests`
  - `beautifulsoup4`

#### Installation des dépendances
```bash
pip install -r requirements.txt
