package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.eqima.scanner.entity.ScanSession;
import org.eqima.scanner.repository.ScanSessionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class AttackSurfaceService {

    private static final Logger log = LoggerFactory.getLogger(AttackSurfaceService.class);

    private static final Set<String> INTERESTING_PATTERNS = Set.of(
            "admin", "api", "login", "auth", "password", "passwd", "register",
            "dashboard", "config", "settings", "backup", "debug", "test", "dev",
            "upload", "file", "download", "export", "import", "token", "secret",
            "wp-admin", "phpmyadmin", "manager", "console", "actuator", "swagger",
            "graphql", "oauth", "reset", "forgot", "internal", "private", "hidden"
    );

    private final WebClient zapClient;
    private final String apiKey;
    private final ScanSessionRepository sessionRepo;
    private final ObjectMapper objectMapper;

    public AttackSurfaceService(WebClient.Builder builder,
                                 @Value("${zap.url}") String zapUrl,
                                 @Value("${zap.api-key}") String apiKey,
                                 ScanSessionRepository sessionRepo,
                                 ObjectMapper objectMapper) {
        this.zapClient = builder.baseUrl(zapUrl).build();
        this.apiKey = apiKey;
        this.sessionRepo = sessionRepo;
        this.objectMapper = objectMapper;
    }

    public Mono<JsonNode> getAttackSurface(String sessionId) {
        return Mono.fromCallable(() -> {
            ScanSession session = sessionRepo.findById(sessionId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                            "Session not found: " + sessionId));

            String targetUrl = session.getTargetUrl();
            ObjectNode root = objectMapper.createObjectNode();
            root.put("targetUrl", targetUrl);
            root.put("targetName", session.getTargetName());
            root.put("sessionStatus", session.getStatus().name());

            // ── URLs découvertes par le spider ─────────────────────────────
            List<String> spiderUrls = fetchSpiderUrls(targetUrl);

            // ── Messages HTTP (méthodes, params, status codes) ─────────────
            List<Map<String, Object>> messages = fetchMessages(targetUrl);

            // ── Construire les endpoints enrichis ─────────────────────────
            Map<String, ObjectNode> endpointMap = new LinkedHashMap<>();

            // Depuis le spider
            for (String url : spiderUrls) {
                String clean = url.split("\\?")[0];
                if (!endpointMap.containsKey(clean)) {
                    ObjectNode ep = objectMapper.createObjectNode();
                    ep.put("url", clean);
                    ep.put("method", "GET");
                    ep.put("statusCode", 0);
                    ep.set("params", objectMapper.createArrayNode());
                    ep.put("interesting", isInteresting(clean));
                    endpointMap.put(clean, ep);
                }
                // Extraire les paramètres GET
                if (url.contains("?")) {
                    String query = url.split("\\?", 2)[1];
                    ArrayNode params = (ArrayNode) endpointMap.get(clean).get("params");
                    Arrays.stream(query.split("&"))
                            .map(p -> p.split("=")[0])
                            .filter(p -> !p.isEmpty())
                            .forEach(p -> {
                                // Éviter les doublons
                                boolean found = false;
                                for (JsonNode n : params) { if (n.asText().equals(p)) { found = true; break; } }
                                if (!found) params.add(p);
                            });
                }
            }

            // Depuis les messages HTTP
            Map<String, Set<String>> methodsByUrl = new LinkedHashMap<>();
            Map<String, Integer> statusByUrl = new LinkedHashMap<>();
            Map<String, String> contentTypeByUrl = new LinkedHashMap<>();
            Map<String, Set<String>> postParamsByUrl = new LinkedHashMap<>();

            for (Map<String, Object> msg : messages) {
                String url = (String) msg.getOrDefault("url", "");
                String method = (String) msg.getOrDefault("method", "GET");
                int status = (int) msg.getOrDefault("status", 0);
                String ct = (String) msg.getOrDefault("contentType", "");
                @SuppressWarnings("unchecked")
                List<String> postParams = (List<String>) msg.getOrDefault("postParams", List.of());

                String clean = url.split("\\?")[0];
                methodsByUrl.computeIfAbsent(clean, k -> new LinkedHashSet<>()).add(method);
                statusByUrl.put(clean, status);
                if (!ct.isEmpty()) contentTypeByUrl.put(clean, ct);
                if (!postParams.isEmpty()) {
                    postParamsByUrl.computeIfAbsent(clean, k -> new LinkedHashSet<>()).addAll(postParams);
                }

                if (!endpointMap.containsKey(clean)) {
                    ObjectNode ep = objectMapper.createObjectNode();
                    ep.put("url", clean);
                    ep.put("method", method);
                    ep.put("statusCode", status);
                    ep.set("params", objectMapper.createArrayNode());
                    ep.put("interesting", isInteresting(clean));
                    endpointMap.put(clean, ep);
                }
            }

            // Enrichir les endpoints avec les données des messages
            for (Map.Entry<String, ObjectNode> entry : endpointMap.entrySet()) {
                String url = entry.getKey();
                ObjectNode ep = entry.getValue();

                Set<String> methods = methodsByUrl.getOrDefault(url, Set.of());
                if (!methods.isEmpty()) {
                    ArrayNode ma = objectMapper.createArrayNode();
                    methods.forEach(ma::add);
                    ep.set("methods", ma);
                    ep.put("method", methods.iterator().next());
                }
                if (statusByUrl.containsKey(url)) ep.put("statusCode", statusByUrl.get(url));
                if (contentTypeByUrl.containsKey(url)) ep.put("contentType", contentTypeByUrl.get(url));

                Set<String> postP = postParamsByUrl.getOrDefault(url, Set.of());
                if (!postP.isEmpty()) {
                    ArrayNode ppa = objectMapper.createArrayNode();
                    postP.forEach(ppa::add);
                    ep.set("postParams", ppa);
                }
            }

            // ── Trier : intéressants en premier, puis par URL ──────────────
            List<ObjectNode> endpoints = new ArrayList<>(endpointMap.values());
            endpoints.sort(Comparator
                    .<ObjectNode, Boolean>comparing(e -> !e.path("interesting").asBoolean())
                    .thenComparing(e -> e.path("url").asText()));

            // ── Résumé ─────────────────────────────────────────────────────
            long interestingCount = endpoints.stream().filter(e -> e.path("interesting").asBoolean()).count();
            long formCount = endpoints.stream().filter(e -> !e.path("postParams").isMissingNode()
                    && e.path("postParams").size() > 0).count();
            Set<String> allMethods = new LinkedHashSet<>();
            methodsByUrl.values().forEach(allMethods::addAll);

            root.put("totalEndpoints", endpoints.size());
            root.put("interestingEndpoints", (int) interestingCount);
            root.put("formsDetected", (int) formCount);
            ArrayNode methodsArr = objectMapper.createArrayNode();
            allMethods.forEach(methodsArr::add);
            root.set("httpMethods", methodsArr);

            ArrayNode epArr = objectMapper.createArrayNode();
            endpoints.forEach(epArr::add);
            root.set("endpoints", epArr);

            return (JsonNode) root;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ─────────────────────────────────────────────────────────────────────────

    private List<String> fetchSpiderUrls(String targetUrl) {
        try {
            JsonNode resp = zapClient.get()
                    .uri("/JSON/core/view/urls/?apikey={key}&baseurl={url}", apiKey, targetUrl)
                    .retrieve().bodyToMono(JsonNode.class)
                    .timeout(Duration.ofSeconds(15)).block();
            List<String> urls = new ArrayList<>();
            if (resp != null && resp.path("urls").isArray()) {
                resp.path("urls").forEach(u -> urls.add(u.asText()));
            }
            return urls;
        } catch (Exception e) {
            log.warn("Could not fetch spider URLs: {}", e.getMessage());
            return List.of();
        }
    }

    private List<Map<String, Object>> fetchMessages(String targetUrl) {
        List<Map<String, Object>> result = new ArrayList<>();
        try {
            int start = 0;
            int pageSize = 200;
            while (true) {
                JsonNode resp = zapClient.get()
                        .uri("/JSON/core/view/messages/?apikey={key}&baseurl={url}&start={s}&count={c}",
                                apiKey, targetUrl, start, pageSize)
                        .retrieve().bodyToMono(JsonNode.class)
                        .timeout(Duration.ofSeconds(20)).block();

                if (resp == null || !resp.path("messages").isArray()) break;
                JsonNode msgs = resp.path("messages");
                if (msgs.isEmpty()) break;

                msgs.forEach(msg -> {
                    JsonNode req = msg.path("requestHeader");
                    JsonNode res = msg.path("responseHeader");
                    if (req.isMissingNode()) return;

                    String header = req.asText("");
                    String[] lines = header.split("\r\n|\n");
                    if (lines.length == 0) return;

                    String[] requestLine = lines[0].split(" ");
                    if (requestLine.length < 2) return;

                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("method", requestLine[0]);
                    m.put("url", requestLine[1].startsWith("http") ? requestLine[1]
                            : targetUrl + requestLine[1]);

                    // Status code depuis la réponse
                    String resHeader = res.asText("");
                    String[] resLines = resHeader.split("\r\n|\n");
                    if (resLines.length > 0) {
                        String[] statusParts = resLines[0].split(" ");
                        if (statusParts.length >= 2) {
                            try { m.put("status", Integer.parseInt(statusParts[1])); }
                            catch (NumberFormatException ignored) { m.put("status", 0); }
                        }
                    }

                    // Content-Type
                    Arrays.stream(resLines)
                            .filter(l -> l.toLowerCase().startsWith("content-type:"))
                            .findFirst()
                            .ifPresent(ct -> m.put("contentType", ct.substring(ct.indexOf(':') + 1).trim()));

                    // Paramètres POST depuis le corps de la requête
                    String body = msg.path("requestBody").asText("");
                    if (!body.isEmpty() && "POST".equals(requestLine[0])) {
                        List<String> postParams = new ArrayList<>();
                        for (String param : body.split("&")) {
                            String[] kv = param.split("=");
                            if (kv.length > 0 && !kv[0].isEmpty()) postParams.add(kv[0]);
                        }
                        if (!postParams.isEmpty()) m.put("postParams", postParams);
                    }

                    result.add(m);
                });

                if (msgs.size() < pageSize) break;
                start += pageSize;
                if (start > 2000) break; // Limite de sécurité
            }
        } catch (Exception e) {
            log.warn("Could not fetch messages: {}", e.getMessage());
        }
        return result;
    }

    private boolean isInteresting(String url) {
        String lower = url.toLowerCase();
        return INTERESTING_PATTERNS.stream().anyMatch(lower::contains);
    }
}