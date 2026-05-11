package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
public class SslService {

    private static final Logger log = LoggerFactory.getLogger(SslService.class);
    private static final String SSL_LABS_BASE = "https://api.ssllabs.com/api/v3";
    private static final int POLL_INTERVAL_MS = 10_000;
    private static final int MAX_POLLS = 60; // 10 min max

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public SslService(WebClient.Builder builder, ObjectMapper objectMapper) {
        this.webClient = builder.baseUrl(SSL_LABS_BASE).build();
        this.objectMapper = objectMapper;
    }

    /**
     * Lance une analyse SSL Labs sur le host et retourne les données JSON sérialisées.
     * Retourne null si l'URL n'est pas HTTPS ou en cas d'erreur.
     */
    public String analyze(String targetUrl) {
        if (targetUrl == null || !targetUrl.startsWith("https://")) {
            return null;
        }

        try {
            String host = URI.create(targetUrl).getHost();
            log.info("Démarrage analyse SSL Labs pour {}", host);

            // Lancer l'analyse
            JsonNode response = webClient.get()
                    .uri("/analyze?host={host}&publish=off&startNew=on&all=done&ignoreMismatch=on", host)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block();

            // Poller jusqu'à READY
            int polls = 0;
            while (polls < MAX_POLLS) {
                if (response == null) break;

                String status = response.path("status").asText("");
                if ("READY".equals(status) || "ERROR".equals(status)) break;

                Thread.sleep(POLL_INTERVAL_MS);
                response = webClient.get()
                        .uri("/analyze?host={host}&publish=off&all=done&ignoreMismatch=on", host)
                        .retrieve()
                        .bodyToMono(JsonNode.class)
                        .block();
                polls++;
            }

            if (response == null || "ERROR".equals(response.path("status").asText(""))) {
                log.warn("SSL Labs analyse échouée pour {}", host);
                return null;
            }

            return parseResult(host, response);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (Exception e) {
            log.warn("Erreur SSL Labs pour {} : {}", targetUrl, e.getMessage());
            return null;
        }
    }

    private String parseResult(String host, JsonNode response) throws Exception {
        JsonNode endpoints = response.path("endpoints");
        if (!endpoints.isArray() || endpoints.isEmpty()) return null;

        JsonNode ep = endpoints.get(0); // Premier endpoint
        JsonNode details = ep.path("details");

        ObjectNode result = objectMapper.createObjectNode();
        result.put("host", host);
        result.put("grade", ep.path("grade").asText("?"));
        result.put("ipAddress", ep.path("ipAddress").asText(""));
        result.put("hasWarnings", ep.path("hasWarnings").asBoolean(false));

        // Certificat
        JsonNode cert = details.path("cert");
        if (!cert.isMissingNode()) {
            result.put("certSubject", cert.path("subject").asText(""));
            result.put("certIssuer", cert.path("issuerLabel").asText(""));
            long notAfterMs = cert.path("notAfter").asLong(0);
            if (notAfterMs > 0) {
                result.put("certExpiry", Instant.ofEpochMilli(notAfterMs).toString());
            }
            long notBeforeMs = cert.path("notBefore").asLong(0);
            if (notBeforeMs > 0) {
                result.put("certValidFrom", Instant.ofEpochMilli(notBeforeMs).toString());
            }
        }

        // Protocoles TLS supportés
        List<String> protocols = new ArrayList<>();
        JsonNode protoArray = details.path("protocols");
        if (protoArray.isArray()) {
            protoArray.forEach(p -> protocols.add(p.path("name").asText("") + " " + p.path("version").asText("")));
        }
        result.set("protocols", objectMapper.valueToTree(protocols));

        // Vulnérabilités connues
        List<String> vulns = new ArrayList<>();
        if (details.path("heartbleed").asBoolean(false))       vulns.add("Heartbleed");
        if (details.path("poodle").asBoolean(false))           vulns.add("POODLE (SSL)");
        if (details.path("poodleTls").asInt(1) == 2)           vulns.add("POODLE (TLS)");
        if (details.path("freak").asBoolean(false))            vulns.add("FREAK");
        if (details.path("logjam").asBoolean(false))           vulns.add("Logjam");
        if (details.path("drownVulnerable").asBoolean(false))  vulns.add("DROWN");
        if (details.path("vulnBeast").asBoolean(false))        vulns.add("BEAST");
        if (details.path("openSslCcs").asInt(1) == 3)         vulns.add("OpenSSL CCS injection");
        if (details.path("ticketbleed").asInt(1) == 2)        vulns.add("Ticketbleed");
        if (details.path("bleichenbacher").asInt(1) == 2 ||
            details.path("bleichenbacher").asInt(1) == 3)     vulns.add("ROBOT (Bleichenbacher)");
        result.set("vulnerabilities", objectMapper.valueToTree(vulns));

        // Suites de chiffrement faibles
        boolean forwardSecrecy = details.path("forwardSecrecy").asInt(0) > 0;
        result.put("forwardSecrecy", forwardSecrecy);

        return objectMapper.writeValueAsString(result);
    }
}