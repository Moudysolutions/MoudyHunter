import subprocess
import requests
import os
from datetime import datetime
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

def banner():
    print("""
      ::::    ::::   ::::::::  :::    ::: :::::::::  :::   :::      
      +:+:+: :+:+:+ :+:    :+: :+:    :+: :+:    :+: :+:   :+:      
      +:+ +:+:+ +:+ +:+    +:+ +:+    +:+ +:+    +:+  +:+ +:+       
      +#+  +:+  +#+ +#+    +:+ +#+    +:+ +#+    +:+   +#++:        
      +#+       +#+ +#+    +#+ +#+    +#+ +#+    +#+    +#+         
      #+#       #+# #+#    #+# #+#    #+# #+#    #+#    #+#         
      ###       ###  ########   ########  #########     ###         
:::    ::: :::    ::: ::::    ::: ::::::::::: :::::::::: :::::::::  
:+:    :+: :+:    :+: :+:+:   :+:     :+:     :+:        :+:    :+: 
+:+    +:+ +:+    +:+ :+:+:+  +:+     +:+     +:+        +:+    +:+ 
+#++:++#++ +#+    +:+ +#+ +:+ +#+     +#+     +#++:++#   +#++:++#:  
+#+    +#+ +#+    +#+ +#+  +#+#+#     +#+     +#+        +#+    +#+ 
#+#    #+# #+#    #+# #+#   #+#+#     #+#     #+#        #+#    #+# 
###    ###  ########  ###    ####     ###     ########## ###    ###                                                             
                  
                  MoudyHunter - by Moudy Solutions
    """)


def detect_target_type(target):
    """
    Détection automatique du type de cible (web, IP, etc.) à l'aide de regex.
    """
    # Vérifie si la cible est une URL
    if re.match(r'^https?://[^\s/$.?#].[^\s]*$', target):
        return "web"
    # Vérifie si la cible est une adresse IP (IPv4)
    elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
        return "network"
    # Vérifie si la cible est un nom de domaine
    elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
        return "domain"
    else:
        return "unknown"


def find_links(target):
    """
    Récupère tous les liens présents sur une page web.
    """
    print("[INFO] Extraction des liens depuis la page cible...")
    try:
        response = requests.get(target, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [urljoin(target, a['href']) for a in soup.find_all('a', href=True)]
        print(f"[INFO] {len(links)} liens trouvés.")
        return links
    except requests.RequestException as e:
        print(f"[ERROR] Erreur lors de l'accès à la page cible : {e}")
        return []

def detect_vulnerable_links(links):
    """
    Identifie les liens avec des paramètres ou des segments dynamiques.
    """
    print("[INFO] Détection des liens potentiellement exploitables...")
    vulnerable_links = []
    for link in links:
        parsed_url = urlparse(link)
        # Vérifie s'il y a des paramètres dans l'URL
        if parsed_url.query:
            vulnerable_links.append(link)
        # Vérifie si l'URL a des segments dynamiques
        elif any(part.isdigit() for part in parsed_url.path.split('/')):
            vulnerable_links.append(link)
    print(f"[INFO] {len(vulnerable_links)} liens exploitables trouvés.")
    return vulnerable_links

def test_sql_injection(links):
    """
    Teste les liens pour des vulnérabilités SQL Injection.
    """
    print("[INFO] Début des tests SQL Injection...")
    vulnerable_params = []
    for link in links:
        parsed_url = urlparse(link)
        query_params = parse_qs(parsed_url.query)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        # Teste les paramètres pour les injections SQL
        for param, values in query_params.items():
            for value in values:
                payload = f"{value}' OR '1'='1"
                test_params = query_params.copy()
                test_params[param] = payload
                test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"

                try:
                    response = requests.get(test_url, timeout=10)
                    if "error" in response.text.lower() or "sql" in response.text.lower():
                        print(f"[ALERT] SQL Injection possible : {test_url}")
                        vulnerable_params.append(test_url)
                    else:
                        print(f"[INFO] Pas de vulnérabilité détectée pour {test_url}.")
                except requests.RequestException as e:
                    print(f"[ERROR] Erreur lors de la requête pour {test_url} : {e}")

    # Résumé des résultats
    if vulnerable_params:
        print("[SUCCESS] SQL Injection détectée sur les liens suivants :")
        for link in vulnerable_params:
            print(f"  - {link}")
    else:
        print("[INFO] Aucune SQL Injection détectée.")
    return vulnerable_params


def test_xss(links):
    """
    Teste les liens pour des vulnérabilités Cross-Site Scripting (XSS).
    """
    print("[INFO] Début des tests Cross-Site Scripting (XSS)...")
    xss_payload = "<script>alert('XSS')</script>"
    vulnerable_links = []

    for link in links:
        parsed_url = urlparse(link)
        query_params = parse_qs(parsed_url.query)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        # Teste les paramètres pour les vulnérabilités XSS
        for param, values in query_params.items():
            for value in values:
                test_params = query_params.copy()
                test_params[param] = xss_payload
                test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"

                try:
                    response = requests.get(test_url, timeout=10)
                    if xss_payload in response.text:
                        print(f"[ALERT] XSS détecté : {test_url}")
                        vulnerable_links.append(test_url)
                    else:
                        print(f"[INFO] Pas de vulnérabilité détectée pour {test_url}.")
                except requests.RequestException as e:
                    print(f"[ERROR] Erreur lors de la requête pour {test_url} : {e}")

    # Résumé des résultats
    if vulnerable_links:
        print("[SUCCESS] Vulnérabilité XSS détectée sur les liens suivants :")
        for link in vulnerable_links:
            print(f"  - {link}")
    else:
        print("[INFO] Aucune vulnérabilité XSS détectée.")
    return vulnerable_links

def test_directory_listing(links):
    """
    Teste les liens pour détecter les répertoires sensibles.
    """
    print("[INFO] Test de la liste des répertoires sensibles...")
    common_dirs = [".git", ".env", "backup", "admin", "test", "config.php"]
    vulnerable_dirs = []

    # Filtre les liens pour rechercher des répertoires sensibles
    for link in links:
        parsed_url = urlparse(link)
        for directory in common_dirs:
            # Construction de l'URL complète pour chaque répertoire sensible
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}/{directory}"

            try:
                response = requests.get(test_url, timeout=10)
                if response.status_code == 200:
                    print(f"[ALERT] Répertoire sensible trouvé : {test_url}")
                    vulnerable_dirs.append(test_url)
                else:
                    print(f"[INFO] Pas de répertoire sensible pour {test_url}.")
            except requests.RequestException as e:
                print(f"[ERROR] Erreur lors de la requête pour {test_url} : {e}")

    # Résumé des résultats
    if vulnerable_dirs:
        print("[SUCCESS] Répertoires sensibles trouvés :")
        for dir_url in vulnerable_dirs:
            print(f"  - {dir_url}")
    else:
        print("[INFO] Aucun répertoire sensible détecté.")
    
    return vulnerable_dirs


def generate_report(target, findings):
    """
    Génération d'un rapport formaté.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"""
=== Rapport de Vulnérabilités ===
Date : {timestamp}
Cible : {target}

=== Résultats ===
"""
    for finding, details in findings.items():
        if details:
            report += f"\n[{finding}] Trouvé :\n{details}\n"
        else:
            report += f"\n[{finding}] Aucun problème détecté.\n"

    # Sauvegarde le rapport dans un fichier
    report_file = f"rapport_{target.replace('://', '_').replace('/', '_')}.txt"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"\n[INFO] Rapport sauvegardé sous : {report_file}")
    return report_file

def main():
    banner()
    target = input("Entrez la cible (URL ou IP) : ").strip()
    target_type = detect_target_type(target)

    if target_type == "unknown":
        print("[ERROR] Type de cible inconnu. Assurez-vous d'utiliser une URL ou une IP valide.")
        return

    print(f"\n[INFO] Type de cible détecté : {target_type}")
    findings = {}

    if target_type == "web":
        links = detect_vulnerable_links(find_links(target))
        findings["SQL Injection"], sql_details = test_sql_injection(links)
        findings["XSS"], xss_details = test_xss(links)
        findings["Directory Listing"], dir_details = test_directory_listing(links)
    elif target_type == "network":
        print("[INFO] Scan réseau non encore implémenté.")
    else:
        print("[ERROR] Type de scan non supporté.")

    # Génération et affichage du rapport
    report_file = generate_report(target, findings)
    print(f"\n[INFO] Rapport prêt à être soumis : {report_file}")

if __name__ == "__main__":
    main()
