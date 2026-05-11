package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Interroge des bases de threat intelligence publiques pour détecter
 * les indicateurs de compromission (IoC) associés à une IP ou un domaine.
 *
 * Sources utilisées :
 *  - URLhaus (abuse.ch)  : URLs malveillantes hébergées sur l'hôte
 *  - Feodo Tracker       : IPs de botnets C2 connues
 */
@Service
public class ThreatIntelService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelService.class);

    private static final WebClient URLHAUS = WebClient.builder()
            .baseUrl("https://urlhaus-api.abuse.ch/v1")
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
                queryUrlhaus(target),
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

    // ── URLhaus ──────────────────────────────────────────────────────────────

    private Mono<JsonNode> queryUrlhaus(String target) {
        return URLHAUS.post()
                .uri("/host/")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("host", target))
                .retrieve()
                .bodyToMono(JsonNode.class)
                .onErrorReturn(mapper.createObjectNode().put("query_status", "error"));
    }

    // ── Feodo Tracker ────────────────────────────────────────────────────────

    private Mono<JsonNode> queryFeodo(String target) {
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
                String ip = entry.path("ip_address").asText("");
                if (ip.equals(target)) {
                    result.put("feodo", true);
                    result.put("malware", entry.path("malware").asText(""));
                    result.put("status", entry.path("status").asText(""));
                    result.put("firstSeen", entry.path("first_seen").asText(""));
                    result.put("lastSeen", entry.path("last_seen").asText(""));
                    result.put("country", entry.path("country").asText(""));
                    break;
                }
            }
        }
        return result;
    }

    // ── Merge results ─────────────────────────────────────────────────────────

    private ObjectNode merge(String target, JsonNode urlhaus, JsonNode feodo) {
        ObjectNode out = mapper.createObjectNode();
        out.put("target", target);

        // URLhaus
        String queryStatus = urlhaus.path("query_status").asText("no_results");
        boolean listedUrlhaus = "is_host".equals(queryStatus);
        out.put("urlhausListed", listedUrlhaus);
        if (listedUrlhaus) {
            out.put("urlhausReference", urlhaus.path("urlhaus_reference").asText(""));
            // Blacklists
            JsonNode bl = urlhaus.path("blacklists");
            out.put("spamhausDbl", bl.path("spamhaus_dbl").asText("not listed"));
            out.put("surbl", bl.path("surbl").asText("not listed"));
            // Tags
            ArrayNode tags = mapper.createArrayNode();
            urlhaus.path("tags").forEach(tags::add);
            out.set("tags", tags);
            // Active malware URLs (max 10)
            ArrayNode urls = mapper.createArrayNode();
            List<JsonNode> allUrls = new java.util.ArrayList<>();
            urlhaus.path("urls").forEach(allUrls::add);
            allUrls.stream()
                   .filter(u -> "online".equals(u.path("url_status").asText()))
                   .limit(5)
                   .forEach(u -> {
                       ObjectNode item = mapper.createObjectNode();
                       item.put("url", u.path("url").asText(""));
                       item.put("status", u.path("url_status").asText(""));
                       item.put("threat", u.path("threat").asText(""));
                       item.put("dateAdded", u.path("date_added").asText(""));
                       item.put("tags", u.path("tags").asText(""));
                       urls.add(item);
                   });
            // if no online, take offline ones
            if (urls.isEmpty()) {
                allUrls.stream().limit(5).forEach(u -> {
                    ObjectNode item = mapper.createObjectNode();
                    item.put("url", u.path("url").asText(""));
                    item.put("status", u.path("url_status").asText(""));
                    item.put("threat", u.path("threat").asText(""));
                    item.put("dateAdded", u.path("date_added").asText(""));
                    urls.add(item);
                });
            }
            out.set("malwareUrls", urls);
        }

        // Feodo Tracker
        boolean feodoListed = feodo.path("feodo").asBoolean(false);
        out.put("feodoListed", feodoListed);
        if (feodoListed) {
            out.put("feodoMalware", feodo.path("malware").asText(""));
            out.put("feodoStatus", feodo.path("status").asText(""));
            out.put("feodoFirstSeen", feodo.path("firstSeen").asText(""));
            out.put("feodoCountry", feodo.path("country").asText(""));
        }

        // Overall threat level
        if (feodoListed) {
            out.put("threatLevel", "critical");
        } else if (listedUrlhaus) {
            String dbl = out.path("spamhausDbl").asText();
            out.put("threatLevel", dbl.contains("listed") ? "high" : "medium");
        } else {
            out.put("threatLevel", "clean");
        }

        return out;
    }
}