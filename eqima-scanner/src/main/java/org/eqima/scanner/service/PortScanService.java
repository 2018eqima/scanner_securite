package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class PortScanService {

    private static final Logger log = LoggerFactory.getLogger(PortScanService.class);

    private final ObjectMapper mapper;

    // Ports à scanner (communs + risqués)
    private static final String PORT_LIST =
        "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636," +
        "993,995,1433,1521,2049,3306,3389,4444,5432,5900,5985,6379," +
        "8080,8443,8888,9200,11211,27017,50000";

    // Niveaux de risque par port
    private static final Map<Integer, PortRisk> RISK_MAP = Map.ofEntries(
        Map.entry(21, new PortRisk("HIGH",
            "FTP transmet identifiants et données en clair. Un attaquant sur le même réseau peut capturer les credentials via sniffing.",
            List.of(
                "Remplacer FTP par SFTP (port 22) ou FTPS (port 990)",
                "Désactiver le service FTP : systemctl disable --now vsftpd (Linux) ou via les fonctionnalités Windows",
                "Si FTP est indispensable, restreindre l'accès par IP dans le firewall",
                "Activer les logs et surveiller les tentatives de connexion"
            ))),
        Map.entry(23, new PortRisk("CRITICAL",
            "Telnet transmet tout en clair (commandes, mots de passe). Protocole obsolète remplacé par SSH depuis les années 2000.",
            List.of(
                "Désactiver immédiatement Telnet : systemctl disable --now telnet (Linux) / désactiver le rôle Telnet Server (Windows)",
                "Utiliser SSH (port 22) à la place pour toute administration distante",
                "Bloquer le port 23 en entrée ET sortie dans le firewall",
                "Vérifier l'absence d'autres accès non chiffrés (rsh, rlogin)"
            ))),
        Map.entry(25, new PortRisk("MEDIUM",
            "Un serveur SMTP ouvert peut être utilisé comme relais pour envoyer du spam ou du phishing, nuisant à la réputation du domaine.",
            List.of(
                "Configurer le relais SMTP pour n'accepter que les connexions authentifiées (SMTP AUTH)",
                "Bloquer le port 25 en sortie pour les IP non autorisées (anti-spam)",
                "Mettre en place SPF, DKIM et DMARC sur le domaine",
                "Utiliser des ports alternatifs chiffrés : 465 (SMTPS) ou 587 (STARTTLS)"
            ))),
        Map.entry(80, new PortRisk("LOW",
            "HTTP transmet les données en clair. Les sessions, cookies et formulaires peuvent être interceptés.",
            List.of(
                "Rediriger tout le trafic HTTP vers HTTPS avec une redirection 301 permanente",
                "Activer HSTS (Strict-Transport-Security) avec une durée minimale de 1 an",
                "Obtenir un certificat SSL/TLS gratuit via Let's Encrypt (Certbot)",
                "Si HTTP est maintenu pour compatibilité, s'assurer qu'aucune donnée sensible n'est transmise"
            ))),
        Map.entry(110, new PortRisk("HIGH",
            "POP3 en clair expose les identifiants et e-mails à l'interception réseau.",
            List.of(
                "Désactiver POP3 en clair (port 110) et activer uniquement POP3S (port 995)",
                "Forcer TLS dans la configuration du serveur mail (Postfix, Dovecot...)",
                "Migrer vers IMAP over TLS (port 993) pour une meilleure gestion multi-appareils",
                "Configurer ssl_min_protocol = TLSv1.2 dans Dovecot"
            ))),
        Map.entry(111, new PortRisk("HIGH",
            "RPC portmapper expose la cartographie des services RPC, utilisé pour attaquer NFS et d'autres services RPC.",
            List.of(
                "Désactiver rpcbind si NFS n'est pas utilisé : systemctl disable --now rpcbind",
                "Bloquer le port 111 (TCP/UDP) en entrée via firewall",
                "Si NFS est nécessaire, restreindre les exports aux seules IPs autorisées dans /etc/exports",
                "Utiliser NFSv4 avec Kerberos plutôt que NFSv3"
            ))),
        Map.entry(135, new PortRisk("HIGH",
            "Le port RPC de Windows est exploité par de nombreux malwares (Blaster, Sasser...) et permet l'énumération de services.",
            List.of(
                "Bloquer le port 135 en entrée via Windows Firewall ou pare-feu réseau",
                "Appliquer tous les correctifs Windows Update, en particulier les bulletins MS-critiques",
                "Désactiver les services RPC non nécessaires via services.msc",
                "Isoler les systèmes Windows des accès directs depuis Internet"
            ))),
        Map.entry(139, new PortRisk("HIGH",
            "NetBIOS permet l'énumération de partages réseau, de comptes et de noms de machines en clair.",
            List.of(
                "Désactiver NetBIOS over TCP/IP : Propriétés réseau > TCP/IP avancé > WINS > Désactiver NetBIOS",
                "Bloquer les ports 137, 138, 139 (TCP/UDP) via firewall",
                "Utiliser uniquement SMBv2/v3 (port 445) pour les partages réseau",
                "Ne jamais exposer NetBIOS ou SMB directement sur Internet"
            ))),
        Map.entry(143, new PortRisk("HIGH",
            "IMAP en clair expose les identifiants et e-mails à l'interception lors de la connexion.",
            List.of(
                "Désactiver IMAP en clair (port 143) et activer uniquement IMAPS (port 993)",
                "Configurer ssl = required dans Dovecot pour forcer le chiffrement",
                "Définir ssl_min_protocol = TLSv1.2 et ssl_cipher_list restrictive",
                "Vérifier que les clients mail sont configurés pour utiliser SSL/TLS"
            ))),
        Map.entry(389, new PortRisk("MEDIUM",
            "LDAP en clair expose les données d'annuaire (utilisateurs, groupes, mots de passe) à l'interception.",
            List.of(
                "Migrer vers LDAPS (port 636) ou activer StartTLS sur le port 389",
                "Restreindre l'accès LDAP aux seuls serveurs applicatifs via firewall",
                "Activer l'authentification SASL et désactiver les liaisons anonymes",
                "Auditer régulièrement les ACLs LDAP avec ldapsearch"
            ))),
        Map.entry(445, new PortRisk("CRITICAL",
            "SMB est le vecteur de WannaCry (EternalBlue/MS17-010), NotPetya et de nombreux ransomwares. Exposition Internet = risque critique.",
            List.of(
                "Bloquer immédiatement le port 445 en entrée depuis Internet via firewall",
                "Appliquer le patch MS17-010 si pas encore fait (Windows Update KB4012212)",
                "Désactiver SMBv1 : Set-SmbServerConfiguration -EnableSMB1Protocol $false (PowerShell)",
                "Activer SMB Signing pour prévenir les attaques de relais NTLM",
                "Exposer SMB uniquement via VPN si l'accès distant est nécessaire"
            ))),
        Map.entry(1433, new PortRisk("HIGH",
            "MSSQL exposé publiquement est ciblé par des scanners automatisés pour bruteforce et exploitation.",
            List.of(
                "Bloquer le port 1433 en entrée via firewall, autoriser uniquement les IPs des serveurs applicatifs",
                "Désactiver ou sécuriser le compte 'sa' : changer le mot de passe, désactiver si non utilisé",
                "Préférer l'authentification Windows intégrée (Kerberos) plutôt que SQL Auth",
                "Changer le port d'écoute par défaut dans SQL Server Configuration Manager",
                "Activer SQL Server Audit pour journaliser les connexions"
            ))),
        Map.entry(1521, new PortRisk("HIGH",
            "Oracle DB exposé publiquement est ciblé pour extraction de données et bruteforce des comptes par défaut.",
            List.of(
                "Bloquer le port 1521 via firewall, n'autoriser que les IPs applicatives",
                "Changer les mots de passe des comptes par défaut (SYS, SYSTEM, DBSNMP...)",
                "Utiliser Oracle Connection Manager (CMAN) pour filtrer les connexions",
                "Activer Oracle Database Vault pour limiter l'accès DBA",
                "Auditer avec Oracle Audit Vault les accès sensibles"
            ))),
        Map.entry(2049, new PortRisk("HIGH",
            "NFS sans restriction permet le montage de partages réseau par n'importe quel client, exposant les fichiers.",
            List.of(
                "Restreindre les exports NFS aux IPs autorisées dans /etc/exports : /data 192.168.1.0/24(rw,sync,no_subtree_check)",
                "Bloquer le port 2049 en entrée depuis Internet via firewall",
                "Utiliser NFSv4 avec Kerberos (krb5p) pour l'authentification et le chiffrement",
                "Désactiver NFSv2 et NFSv3 si non nécessaires",
                "Exécuter exportfs -ra après modification de /etc/exports"
            ))),
        Map.entry(3306, new PortRisk("HIGH",
            "MySQL/MariaDB exposé publiquement est ciblé pour bruteforce, injection SQL et vol de données.",
            List.of(
                "Configurer MySQL pour écouter uniquement en local : bind-address = 127.0.0.1 dans my.cnf",
                "Supprimer les comptes anonymes : DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;",
                "Si accès distant nécessaire, utiliser un tunnel SSH plutôt qu'exposer le port directement",
                "Appliquer le principe du moindre privilège : GRANT uniquement les droits nécessaires",
                "Exécuter mysql_secure_installation pour supprimer les configurations par défaut"
            ))),
        Map.entry(3389, new PortRisk("HIGH",
            "RDP est massivement ciblé par des bruteforce automatisés et des ransomwares (Ryuk, REvil...) qui s'y connectent directement.",
            List.of(
                "Ne jamais exposer RDP directement sur Internet — utiliser un VPN ou un bastion SSH",
                "Activer l'authentification NLA (Network Level Authentication) pour pré-authentification",
                "Changer le port par défaut 3389 vers un port non standard (sécurité par obscurité + réduction du bruit)",
                "Configurer une politique de verrouillage de compte (Account Lockout Policy)",
                "Activer la journalisation des connexions RDP et alerter sur les échecs répétés"
            ))),
        Map.entry(4444, new PortRisk("CRITICAL",
            "Le port 4444 est le port par défaut de Metasploit Meterpreter. Sa présence indique très probablement un système compromis.",
            List.of(
                "Isoler immédiatement le système du réseau en attendant l'investigation forensique",
                "Identifier le processus écoutant sur ce port : ss -tlnp | grep 4444 (Linux) / netstat -ano (Windows)",
                "Analyser le système avec un antimalware hors-ligne (live CD) et un rootkit scanner",
                "Capturer la mémoire vive avant extinction pour analyse forensique",
                "Documenter la compromission et contacter un CSIRT si nécessaire"
            ))),
        Map.entry(5432, new PortRisk("HIGH",
            "PostgreSQL exposé publiquement permet des tentatives de bruteforce et d'exploitation des rôles par défaut.",
            List.of(
                "Configurer listen_addresses = 'localhost' dans postgresql.conf",
                "Restreindre les connexions dans pg_hba.conf par IP et méthode d'authentification",
                "Si accès distant nécessaire, utiliser SSL : ssl = on dans postgresql.conf + tunnel SSH",
                "Supprimer ou désactiver le rôle postgres si non utilisé comme superutilisateur",
                "Appliquer le principe du moindre privilège sur les rôles applicatifs"
            ))),
        Map.entry(5900, new PortRisk("HIGH",
            "VNC expose l'interface graphique avec souvent un mot de passe faible ou absent, permettant la prise de contrôle totale.",
            List.of(
                "Désactiver VNC si non utilisé : systemctl disable --now vncserver",
                "Si VNC nécessaire, accéder uniquement via tunnel SSH : ssh -L 5900:localhost:5900 user@host",
                "Configurer un mot de passe fort dans ~/.vnc/passwd",
                "Bloquer le port 5900 en entrée via firewall",
                "Préférer des alternatives modernes et chiffrées (RDP over VPN, Guacamole)"
            ))),
        Map.entry(5985, new PortRisk("MEDIUM",
            "WinRM permet l'administration distante PowerShell. En clair (HTTP), les commandes et credentials sont interceptables.",
            List.of(
                "Activer HTTPS pour WinRM : winrm quickconfig -transport:https",
                "Restreindre les hôtes autorisés : winrm set winrm/config/client @{TrustedHosts=\"IP_autorisée\"}",
                "Désactiver WinRM si non utilisé : winrm delete winrm/config/Listener?Address=*+Transport=HTTP",
                "Utiliser JEA (Just Enough Administration) pour limiter les commandes autorisées"
            ))),
        Map.entry(6379, new PortRisk("CRITICAL",
            "Redis sans authentification permet l'accès en lecture/écriture à toutes les données et l'exécution de commandes système via CONFIG SET.",
            List.of(
                "Configurer bind 127.0.0.1 dans redis.conf pour n'écouter qu'en local",
                "Activer l'authentification : requirepass <mot_de_passe_fort_256bits>",
                "Désactiver les commandes dangereuses : rename-command CONFIG \"\" / rename-command FLUSHALL \"\"",
                "Bloquer le port 6379 via firewall en entrée",
                "Activer TLS dans Redis 6+ : tls-port 6380, tls-cert-file, tls-key-file"
            ))),
        Map.entry(8080, new PortRisk("LOW",
            "Un port HTTP alternatif expose souvent un panneau d'administration ou un proxy sans chiffrement.",
            List.of(
                "Identifier le service : curl -I http://cible:8080 et vérifier si un accès admin est exposé",
                "Restreindre l'accès via firewall si le service est à usage interne",
                "Rediriger vers HTTPS si le service doit rester accessible",
                "Vérifier que le service est à jour et correctement authentifié"
            ))),
        Map.entry(8443, new PortRisk("LOW",
            "Un port HTTPS alternatif expose souvent un panneau d'administration dont le certificat peut être auto-signé.",
            List.of(
                "Vérifier la validité et l'autorité du certificat SSL présenté",
                "Identifier le service exposé et restreindre l'accès si nécessaire",
                "Mettre à jour le service régulièrement",
                "Si usage interne, bloquer depuis Internet via firewall"
            ))),
        Map.entry(8888, new PortRisk("MEDIUM",
            "Jupyter Notebook exposé sans authentification permet l'exécution de code Python arbitraire sur le serveur (RCE).",
            List.of(
                "Ne jamais exposer Jupyter directement sur Internet",
                "Configurer un mot de passe : jupyter notebook password",
                "Accéder uniquement via tunnel SSH : ssh -L 8888:localhost:8888 user@host",
                "Utiliser JupyterHub avec authentification OAuth/LDAP pour les déploiements multi-utilisateurs",
                "Bloquer le port 8888 en entrée via firewall"
            ))),
        Map.entry(9200, new PortRisk("CRITICAL",
            "Elasticsearch sans authentification expose toutes les données indexées en lecture et écriture sans restriction.",
            List.of(
                "Configurer network.host: 127.0.0.1 ou une IP interne dans elasticsearch.yml",
                "Activer X-Pack Security (gratuit depuis ES 6.8) : xpack.security.enabled: true",
                "Créer des utilisateurs avec les rôles minimaux nécessaires",
                "Bloquer le port 9200 (et 9300) en entrée depuis Internet via firewall",
                "Activer TLS pour les communications nœud-à-nœud et client-serveur"
            ))),
        Map.entry(11211, new PortRisk("HIGH",
            "Memcached sans authentification est utilisé pour des attaques d'amplification DDoS (facteur x51000) et expose toutes les données en cache.",
            List.of(
                "Configurer Memcached pour écouter uniquement en local : -l 127.0.0.1 dans /etc/memcached.conf",
                "Bloquer le port 11211 (TCP et UDP) en entrée via firewall — surtout l'UDP utilisé pour l'amplification DDoS",
                "Activer SASL pour l'authentification si Memcached >= 1.4.3",
                "Désactiver l'UDP si non utilisé : -U 0 dans les options de démarrage"
            ))),
        Map.entry(27017, new PortRisk("CRITICAL",
            "MongoDB sans authentification expose toutes les bases de données en lecture/écriture/suppression sans restriction.",
            List.of(
                "Activer l'authentification : security.authorization: enabled dans mongod.conf",
                "Configurer net.bindIp: 127.0.0.1 pour n'écouter qu'en local",
                "Bloquer le port 27017 en entrée via firewall",
                "Créer des utilisateurs avec les rôles minimaux : db.createUser({...roles:[{role:'readWrite', db:'mydb'}]})",
                "Activer TLS : net.tls.mode: requireTLS dans mongod.conf"
            ))),
        Map.entry(50000, new PortRisk("HIGH",
            "Le port 50000 est utilisé par Jenkins (Java JNLP) et SAP. Une exposition publique permet l'accès à des agents de build ou à des interfaces d'administration.",
            List.of(
                "Désactiver l'agent Jenkins JNLP si non utilisé : Administrer Jenkins > Configurer la sécurité globale > désactiver le port TCP",
                "Restreindre l'accès via firewall aux seuls serveurs autorisés",
                "Si Jenkins, activer l'authentification et désactiver l'accès anonyme",
                "Mettre à jour Jenkins régulièrement (nombreuses CVEs critiques historiquement)"
            )))
    );

    public PortScanService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public Mono<ObjectNode> scan(String target) {
        return Mono.fromCallable(() -> runScan(target))
                   .subscribeOn(Schedulers.boundedElastic())
                   .onErrorResume(e -> {
                       log.warn("Port scan failed for {}: {}", target, e.getMessage());
                       ObjectNode err = mapper.createObjectNode();
                       err.put("target", target);
                       err.put("error", e.getMessage());
                       return Mono.just(err);
                   });
    }

    private ObjectNode runScan(String target) throws Exception {
        long start = System.currentTimeMillis();

        // -sT : TCP connect scan (no root needed)
        // -T4 : timing agressif
        // --open : only open ports
        // -oG - : grepable output to stdout
        List<String> cmd = new ArrayList<>(List.of(
            "nmap", "-sT", "-T4", "--open", "-p", PORT_LIST, "-oG", "-", target
        ));

        log.info("Running: {}", String.join(" ", cmd));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        int exitCode = proc.waitFor();
        log.info("nmap exited {} for {}", exitCode, target);

        long duration = System.currentTimeMillis() - start;
        return buildResult(target, output.toString(), duration);
    }

    private ObjectNode buildResult(String target, String nmapOutput, long durationMs) {
        ObjectNode out = mapper.createObjectNode();
        out.put("target", target);
        out.put("scanDuration", durationMs / 1000.0);

        ArrayNode ports = mapper.createArrayNode();
        int critical = 0, high = 0, medium = 0, low = 0;
        String resolvedIp = "";

        for (String line : nmapOutput.split("\n")) {
            // Extract resolved IP from "Host: IP (hostname)"
            if (line.startsWith("Host:") && resolvedIp.isEmpty()) {
                String[] parts = line.split("\\s+");
                if (parts.length > 1) resolvedIp = parts[1];
            }
            // Parse ports line: "Host: IP\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///"
            if (line.contains("Ports:")) {
                int idx = line.indexOf("Ports:");
                String portsPart = line.substring(idx + 6).trim();
                for (String entry : portsPart.split(",\\s*")) {
                    String[] fields = entry.trim().split("/");
                    if (fields.length < 3) continue;
                    try {
                        int portNum = Integer.parseInt(fields[0]);
                        String state = fields[1];
                        String proto = fields[2];
                        String service = fields.length > 4 ? fields[4] : "";

                        ObjectNode portNode = mapper.createObjectNode();
                        portNode.put("port", portNum);
                        portNode.put("protocol", proto);
                        portNode.put("service", service);
                        portNode.put("state", state);

                        PortRisk risk = RISK_MAP.get(portNum);
                        if (risk != null) {
                            portNode.put("risk", risk.level);
                            portNode.put("reason", risk.reason);
                            ArrayNode remArr = mapper.createArrayNode();
                            risk.remediation.forEach(remArr::add);
                            portNode.set("remediation", remArr);
                            switch (risk.level) {
                                case "CRITICAL" -> critical++;
                                case "HIGH"     -> high++;
                                case "MEDIUM"   -> medium++;
                                case "LOW"      -> low++;
                            }
                        } else {
                            portNode.put("risk", "INFO");
                            portNode.put("reason", "Port ouvert — vérifier si nécessaire");
                            ArrayNode remArr = mapper.createArrayNode();
                            remArr.add("Identifier le service et vérifier s'il est nécessaire");
                            remArr.add("Bloquer le port via firewall s'il n'est pas utilisé");
                            portNode.set("remediation", remArr);
                        }
                        ports.add(portNode);
                    } catch (NumberFormatException ignored) {}
                }
            }
        }

        out.put("resolvedIp", resolvedIp.isEmpty() ? target : resolvedIp);
        out.set("ports", ports);

        ObjectNode summary = mapper.createObjectNode();
        summary.put("critical", critical);
        summary.put("high", high);
        summary.put("medium", medium);
        summary.put("low", low);
        summary.put("info", ports.size() - critical - high - medium - low);
        summary.put("total", ports.size());
        out.set("riskSummary", summary);

        // Overall risk level
        String overallRisk = critical > 0 ? "CRITICAL"
                           : high > 0     ? "HIGH"
                           : medium > 0   ? "MEDIUM"
                           : low > 0      ? "LOW"
                           : ports.isEmpty() ? "UNKNOWN" : "INFO";
        out.put("overallRisk", overallRisk);

        return out;
    }

    private record PortRisk(String level, String reason, List<String> remediation) {}
}