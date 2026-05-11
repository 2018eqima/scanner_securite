package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.net.InetAddress;
import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class SubdomainDiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(SubdomainDiscoveryService.class);
    private static final Pattern SUBDOMAIN_PATTERN = Pattern.compile("^[a-zA-Z0-9*][a-zA-Z0-9\\-.*]*$");

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public SubdomainDiscoveryService(WebClient.Builder builder, ObjectMapper objectMapper) {
        this.webClient = builder
                .defaultHeader("User-Agent", "Mozilla/5.0 (compatible; EqimaScanner/1.0)")
                .defaultHeader("Accept", "application/json, text/plain, */*")
                .baseUrl("https://crt.sh")
                .build();
        this.objectMapper = objectMapper;
    }

    public Mono<List<Map<String, Object>>> discover(String domain) {
        String cleanDomain = domain.replaceAll("https?://", "").replaceAll("/.*", "").toLowerCase().trim();

        return fetchFromCrtSh(cleanDomain)
                .collectList()
                .flatMap(subdomains -> resolveAll(subdomains, cleanDomain))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Flux<String> fetchFromCrtSh(String domain) {
        return webClient.get()
                .uri("/?q=%25.{domain}&output=json", domain)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(25))
                .flatMapMany(json -> parseCrtShJson(json, domain))
                .onErrorResume(e -> {
                    log.warn("crt.sh failed for {}: {} — trying HackerTarget fallback", domain, e.getMessage());
                    return fetchFromHackerTarget(domain);
                });
    }

    private Flux<String> fetchFromHackerTarget(String domain) {
        WebClient htClient = WebClient.builder()
                .baseUrl("https://api.hackertarget.com")
                .defaultHeader("User-Agent", "Mozilla/5.0 (compatible; EqimaScanner/1.0)")
                .build();
        return htClient.get()
                .uri("/hostsearch/?q={domain}", domain)
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(20))
                .flatMapMany(text -> {
                    Set<String> found = new LinkedHashSet<>();
                    found.add(domain);
                    for (String line : text.split("\n")) {
                        String[] parts = line.split(",");
                        if (parts.length >= 1) {
                            String sub = parts[0].trim().toLowerCase();
                            if (!sub.isEmpty() && !sub.startsWith("error")
                                    && (sub.equals(domain) || sub.endsWith("." + domain))) {
                                found.add(sub);
                            }
                        }
                    }
                    log.info("HackerTarget found {} subdomains for {}", found.size(), domain);
                    return Flux.fromIterable(found);
                })
                .onErrorResume(e -> {
                    log.warn("HackerTarget also failed for {}: {}", domain, e.getMessage());
                    return Flux.just(domain);
                });
    }

    private Flux<String> parseCrtShJson(String json, String domain) {
        Set<String> found = new LinkedHashSet<>();
        try {
            JsonNode arr = objectMapper.readTree(json);
            if (arr.isArray()) {
                for (JsonNode entry : arr) {
                    String nameValue = entry.path("name_value").asText("");
                    for (String name : nameValue.split("\n")) {
                        name = name.trim().toLowerCase();
                        if (!name.startsWith("*") && name.endsWith("." + domain)
                                && SUBDOMAIN_PATTERN.matcher(name).matches()) {
                            found.add(name);
                        }
                    }
                    String commonName = entry.path("common_name").asText("").trim().toLowerCase();
                    if (!commonName.startsWith("*") && (commonName.equals(domain)
                            || commonName.endsWith("." + domain))) {
                        found.add(commonName);
                    }
                }
            }
            if (found.isEmpty()) {
                throw new RuntimeException("crt.sh returned empty results");
            }
        } catch (Exception e) {
            log.warn("crt.sh parse error: {}", e.getMessage());
            return Flux.error(e);
        }
        found.add(domain);
        log.info("crt.sh found {} unique subdomains for {}", found.size(), domain);
        return Flux.fromIterable(found);
    }

    private static final WebClient GEO_CLIENT = WebClient.builder()
            .baseUrl("http://ip-api.com")
            .defaultHeader("User-Agent", "EqimaScanner/1.0")
            .defaultHeader("Content-Type", "application/json")
            .build();

    private Mono<List<Map<String, Object>>> resolveAll(List<String> subdomains, String rootDomain) {
        return Mono.fromCallable(() -> {
            // Résolution DNS en parallèle
            List<Map<String, Object>> results = new ArrayList<>();
            for (String sub : subdomains) {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("subdomain", sub);
                r.put("active", false);
                r.put("ip", "");
                r.put("httpsUrl", "https://" + sub);
                r.put("httpUrl", "http://" + sub);
                r.put("country", "");
                r.put("countryCode", "");
                r.put("city", "");
                r.put("org", "");
                try {
                    InetAddress addr = InetAddress.getByName(sub);
                    r.put("ip", addr.getHostAddress());
                    r.put("active", true);
                } catch (Exception ignored) {}
                results.add(r);
            }

            // Géolocalisation en batch pour les actifs (ip-api.com batch: 100 max)
            List<Map<String, Object>> actifs = results.stream()
                    .filter(r -> (Boolean) r.get("active"))
                    .toList();
            if (!actifs.isEmpty()) {
                batchGeolocate(actifs);
            }

            // Trier : actifs d'abord, puis par nom
            results.sort(Comparator
                    .<Map<String, Object>, Boolean>comparing(r -> !(Boolean) r.get("active"))
                    .thenComparing(r -> (String) r.get("subdomain")));
            return results;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private void batchGeolocate(List<Map<String, Object>> actifs) {
        try {
            // Construire la liste d'IPs pour le batch
            List<String> ips = actifs.stream()
                    .map(r -> (String) r.get("ip"))
                    .filter(ip -> !ip.isEmpty())
                    .distinct()
                    .limit(100)
                    .toList();
            if (ips.isEmpty()) return;

            // Payload JSON: [{"query":"ip1","fields":"..."}, ...]
            com.fasterxml.jackson.databind.node.ArrayNode payload = objectMapper.createArrayNode();
            for (String ip : ips) {
                com.fasterxml.jackson.databind.node.ObjectNode entry = objectMapper.createObjectNode();
                entry.put("query", ip);
                entry.put("fields", "status,country,countryCode,city,org,query");
                payload.add(entry);
            }

            JsonNode response = GEO_CLIENT.post()
                    .uri("/batch")
                    .bodyValue(payload.toString())
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .timeout(Duration.ofSeconds(10))
                    .block();

            if (response != null && response.isArray()) {
                Map<String, JsonNode> geoByIp = new LinkedHashMap<>();
                for (JsonNode geo : response) {
                    String q = geo.path("query").asText("");
                    if ("success".equals(geo.path("status").asText(""))) {
                        geoByIp.put(q, geo);
                    }
                }
                // Enrichir les résultats
                for (Map<String, Object> r : actifs) {
                    String ip = (String) r.get("ip");
                    JsonNode geo = geoByIp.get(ip);
                    if (geo != null) {
                        r.put("country", geo.path("country").asText(""));
                        r.put("countryCode", geo.path("countryCode").asText("").toLowerCase());
                        r.put("city", geo.path("city").asText(""));
                        r.put("org", geo.path("org").asText(""));
                    }
                }
                log.info("Batch geo resolved {}/{} IPs", geoByIp.size(), ips.size());
            }
        } catch (Exception e) {
            log.warn("Batch geo failed: {}", e.getMessage());
        }
    }
}