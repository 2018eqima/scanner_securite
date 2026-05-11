package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.eqima.scanner.entity.Finding;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class ZapService {

    private final WebClient zapClient;
    private final String apiKey;

    public ZapService(WebClient.Builder builder,
                      @Value("${zap.url}") String zapUrl,
                      @Value("${zap.api-key}") String apiKey) {
        this.zapClient = builder
                .baseUrl(zapUrl)
                .build();
        this.apiKey = apiKey;
    }

    public Mono<String> startSpider(String targetUrl) {
        return zapClient.get()
                .uri("/JSON/spider/action/scan/?apikey={key}&url={url}&recurse=true", apiKey, targetUrl)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(json -> json.path("scan").asText());
    }

    public Mono<Integer> getSpiderProgress(String spiderId) {
        return zapClient.get()
                .uri("/JSON/spider/view/status/?apikey={key}&scanId={id}", apiKey, spiderId)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(json -> json.path("status").asInt(0));
    }

    public Mono<String> startActiveScan(String targetUrl) {
        return zapClient.get()
                .uri("/JSON/ascan/action/scan/?apikey={key}&url={url}&recurse=true", apiKey, targetUrl)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(json -> json.path("scan").asText());
    }

    public Mono<Integer> getScanProgress(String scanId) {
        return zapClient.get()
                .uri("/JSON/ascan/view/status/?apikey={key}&scanId={id}", apiKey, scanId)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(json -> json.path("status").asInt(0));
    }

    public Mono<List<Finding>> getAlerts(String baseUrl, String sessionId) {
        return zapClient.get()
                .uri("/JSON/alert/view/alerts/?apikey={key}&baseurl={url}", apiKey, baseUrl)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(json -> {
                    List<Finding> findings = new ArrayList<>();
                    JsonNode alerts = json.path("alerts");
                    if (alerts.isArray()) {
                        alerts.forEach(alert -> findings.add(mapAlert(alert, sessionId)));
                    }
                    return findings;
                });
    }

    // Package-private pour les tests unitaires
    static Finding mapAlert(JsonNode alert, String sessionId) {
        Finding f = new Finding();
        f.setId(UUID.randomUUID().toString());
        f.setSessionId(sessionId);
        f.setUrl(alert.path("url").asText(""));
        f.setName(alert.path("name").asText("Unknown"));
        f.setDescription(alert.path("description").asText(""));
        f.setSolution(alert.path("solution").asText(""));
        f.setReference(alert.path("reference").asText(""));
        f.setSeverity(mapSeverity(alert.path("risk").asText("")));
        f.setEvidence(alert.path("evidence").asText(""));
        f.setCweid(alert.path("cweid").asText(""));
        f.setWascid(alert.path("wascid").asText(""));
        f.setDetectedAt(Instant.now());
        return f;
    }

    static Finding.Severity mapSeverity(String risk) {
        return switch (risk.toLowerCase()) {
            case "high" -> Finding.Severity.HIGH;
            case "medium" -> Finding.Severity.MEDIUM;
            case "low" -> Finding.Severity.LOW;
            default -> Finding.Severity.INFORMATIONAL;
        };
    }
}