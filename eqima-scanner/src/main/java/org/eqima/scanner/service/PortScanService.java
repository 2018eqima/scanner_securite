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
        Map.entry(21,    new PortRisk("HIGH",   "FTP — transfert en clair, credentials exposés")),
        Map.entry(23,    new PortRisk("CRITICAL","Telnet — protocole non chiffré, remplacé par SSH")),
        Map.entry(25,    new PortRisk("MEDIUM",  "SMTP ouvert — risque de relais ouvert (spam)")),
        Map.entry(80,    new PortRisk("LOW",     "HTTP non chiffré — données en clair")),
        Map.entry(110,   new PortRisk("HIGH",    "POP3 — protocole mail non chiffré")),
        Map.entry(111,   new PortRisk("HIGH",    "RPC portmapper — vecteur d'attaque NFS")),
        Map.entry(135,   new PortRisk("HIGH",    "RPC Windows — exploité par de nombreux malwares")),
        Map.entry(139,   new PortRisk("HIGH",    "NetBIOS — partage réseau Windows non chiffré")),
        Map.entry(143,   new PortRisk("HIGH",    "IMAP — protocole mail non chiffré")),
        Map.entry(389,   new PortRisk("MEDIUM",  "LDAP — annuaire en clair, privilégier LDAPS")),
        Map.entry(445,   new PortRisk("CRITICAL","SMB — exploité par WannaCry, EternalBlue, etc.")),
        Map.entry(1433,  new PortRisk("HIGH",    "MSSQL exposé publiquement")),
        Map.entry(1521,  new PortRisk("HIGH",    "Oracle DB exposé publiquement")),
        Map.entry(2049,  new PortRisk("HIGH",    "NFS — partage de fichiers sans authentification forte")),
        Map.entry(3306,  new PortRisk("HIGH",    "MySQL/MariaDB exposé publiquement")),
        Map.entry(3389,  new PortRisk("HIGH",    "RDP — cible de bruteforce et ransomwares")),
        Map.entry(4444,  new PortRisk("CRITICAL","Port Metasploit — indicateur de compromission probable")),
        Map.entry(5432,  new PortRisk("HIGH",    "PostgreSQL exposé publiquement")),
        Map.entry(5900,  new PortRisk("HIGH",    "VNC — accès bureau à distance souvent non protégé")),
        Map.entry(5985,  new PortRisk("MEDIUM",  "WinRM — administration Windows à distance")),
        Map.entry(6379,  new PortRisk("CRITICAL","Redis — souvent sans authentification, RCE possible")),
        Map.entry(8080,  new PortRisk("LOW",     "HTTP alternatif — souvent panneau admin ou proxy")),
        Map.entry(8443,  new PortRisk("LOW",     "HTTPS alternatif — souvent panneau admin")),
        Map.entry(8888,  new PortRisk("MEDIUM",  "Jupyter Notebook — souvent sans auth, RCE possible")),
        Map.entry(9200,  new PortRisk("CRITICAL","Elasticsearch — données exposées sans auth par défaut")),
        Map.entry(11211, new PortRisk("HIGH",    "Memcached — amplification DDoS, pas d'auth")),
        Map.entry(27017, new PortRisk("CRITICAL","MongoDB — souvent sans auth, données exposées")),
        Map.entry(50000, new PortRisk("HIGH",    "SAP / Jenkins — accès administration"))
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
                            switch (risk.level) {
                                case "CRITICAL" -> critical++;
                                case "HIGH"     -> high++;
                                case "MEDIUM"   -> medium++;
                                case "LOW"      -> low++;
                            }
                        } else {
                            portNode.put("risk", "INFO");
                            portNode.put("reason", "Port ouvert — vérifier si nécessaire");
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

    private record PortRisk(String level, String reason) {}
}