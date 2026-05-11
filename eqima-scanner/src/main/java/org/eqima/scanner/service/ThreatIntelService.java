package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

/**
 * Interroge des bases de threat intelligence publiques (sans clé API) pour
 * détecter les indicateurs de compromission associés à une IP ou un domaine.
 *
 * Sources :
 *  - Shodan InternetDB  : ports ouverts, CVEs, tags malware (gratuit, sans clé)
 *  - Feodo Tracker      : IPs de botnets C2 connus (Emotet, Trickbot, etc.)
 */
@Service
public class ThreatIntelService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelService.class);

    private static final WebClient SHODAN = WebClient.builder()
            .baseUrl("https://internetdb.shodan.io")
            .defaultHeader("User-Agent", "EqimaScanner/1.0")
            .build();

    private static final WebClient FEODO = WebClient.builder()
            .baseUrl("https://feodotracker.abuse.ch")
            .defaultHeader("User-Agent", "EqimaScanner/1.0")
            .build();

    private final ObjectMapper mapper;

    public ThreatIntelService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public Mono<ObjectNode> check(String target) {
        return Mono.zip(
                queryShodan(target),
                queryFeodo(target)
        ).map(tuple -> merge(target, tuple.getT1(), tuple.getT2()))
         .onErrorResume(e -> {
             log.warn("ThreatIntel check failed for {}: {}", target, e.getMessage());
             ObjectNode err = mapper.createObjectNode();
             err.put("target", target);
             err.put("error", e.getMessage());
             err.put("threatLevel", "unknown");
             return Mono.just(err);
         });
    }

    // ── Shodan InternetDB ─────────────────────────────────────────────────────

    private Mono<JsonNode> queryShodan(String target) {
        // InternetDB only works for IPs, not domains
        boolean isIp = target.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
        if (!isIp) return Mono.just(mapper.createObjectNode().put("shodan", false));

        return SHODAN.get()
                .uri("/{ip}", target)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .onErrorReturn(mapper.createObjectNode().put("shodan", false));
    }

    // ── Feodo Tracker ─────────────────────────────────────────────────────────

    private Mono<JsonNode> queryFeodo(String target) {
        boolean isIp = target.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
        if (!isIp) return Mono.just(mapper.createObjectNode().put("feodo", false));

        return FEODO.get()
                .uri("/downloads/ipblocklist.json")
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(json -> checkFeodo(json, target))
                .onErrorReturn(mapper.createObjectNode().put("feodo", false));
    }

    private JsonNode checkFeodo(JsonNode feodoList, String target) {
        ObjectNode result = mapper.createObjectNode();
        result.put("feodo", false);
        if (feodoList.isArray()) {
            for (JsonNode entry : feodoList) {
                if (target.equals(entry.path("ip_address").asText(""))) {
                    result.put("feodo", true);
                    result.put("malware", entry.path("malware").asText(""));
                    result.put("status", entry.path("status").asText(""));
                    result.put("firstSeen", entry.path("first_seen").asText(""));
                    result.put("lastOnline", entry.path("last_online").asText(""));
                    result.put("country", entry.path("country").asText(""));
                    result.put("asName", entry.path("as_name").asText(""));
                    break;
                }
            }
        }
        return result;
    }

    // ── Merge ─────────────────────────────────────────────────────────────────

    private ObjectNode merge(String target, JsonNode shodan, JsonNode feodo) {
        ObjectNode out = mapper.createObjectNode();
        out.put("target", target);

        // Shodan InternetDB
        boolean hasShodan = shodan.has("ip");
        out.put("shodanAvailable", hasShodan);
        if (hasShodan) {
            // Open ports
            ArrayNode ports = mapper.createArrayNode();
            shodan.path("ports").forEach(ports::add);
            out.set("openPorts", ports);

            // CVEs
            ArrayNode cves = mapper.createArrayNode();
            shodan.path("vulns").forEach(cves::add);
            out.set("cves", cves);

            // Tags (malware, vpn, tor, botnet, etc.)
            ArrayNode tags = mapper.createArrayNode();
            shodan.path("tags").forEach(tags::add);
            out.set("tags", tags);

            // Hostnames
            ArrayNode hostnames = mapper.createArrayNode();
            shodan.path("hostnames").forEach(hostnames::add);
            out.set("hostnames", hostnames);

            // CPEs (detected software)
            ArrayNode cpes = mapper.createArrayNode();
            shodan.path("cpes").forEach(cpes::add);
            out.set("cpes", cpes);

            out.put("shodanRef", "https://www.shodan.io/host/" + target);
        }

        // Feodo
        boolean feodoListed = feodo.path("feodo").asBoolean(false);
        out.put("feodoListed", feodoListed);
        if (feodoListed) {
            out.put("feodoMalware", feodo.path("malware").asText(""));
            out.put("feodoStatus", feodo.path("status").asText(""));
            out.put("feodoFirstSeen", feodo.path("firstSeen").asText(""));
            out.put("feodoLastOnline", feodo.path("lastOnline").asText(""));
            out.put("feodoCountry", feodo.path("country").asText(""));
            out.put("feodoAsName", feodo.path("asName").asText(""));
        }

        // Threat level
        if (feodoListed) {
            out.put("threatLevel", "critical");
        } else if (hasShodan) {
            List<String> tagList = new ArrayList<>();
            shodan.path("tags").forEach(t -> tagList.add(t.asText().toLowerCase()));
            boolean maliciousTags = tagList.stream().anyMatch(t ->
                t.contains("malware") || t.contains("botnet") || t.contains("c2") ||
                t.contains("ransomware") || t.contains("spam"));
            int cveCount = shodan.path("vulns").size();
            if (maliciousTags) {
                out.put("threatLevel", "high");
            } else if (cveCount >= 5) {
                out.put("threatLevel", "medium");
            } else if (cveCount > 0) {
                out.put("threatLevel", "low");
            } else {
                out.put("threatLevel", "clean");
            }
        } else {
            out.put("threatLevel", "clean");
        }

        return out;
    }
}