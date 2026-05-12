package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.*;

@Service
public class WaybackService {

    private static final Logger log = LoggerFactory.getLogger(WaybackService.class);

    private final WebClient cdx = WebClient.builder()
        .baseUrl("http://web.archive.org")
        .defaultHeader("User-Agent", "EqimaScanner/1.0")
        .build();

    public record WaybackResult(String domain, List<WaybackUrl> urls) {}
    public record WaybackUrl(String url, String statusCode, String mimeType, String timestamp) {}

    /** Fetch up to 200 historical URLs for *.domain from Wayback CDX */
    public WaybackResult fetch(String domain) {
        try {
            // CDX API: output=json, fl=original,statuscode,mimetype,timestamp, collapse=urlkey, limit=200
            String body = cdx.get()
                .uri(uriBuilder -> uriBuilder
                    .path("/cdx/search/cdx")
                    .queryParam("url", "*." + domain + "/*")
                    .queryParam("output", "json")
                    .queryParam("fl", "original,statuscode,mimetype,timestamp")
                    .queryParam("collapse", "urlkey")
                    .queryParam("limit", "200")
                    .queryParam("filter", "statuscode:200")
                    .build())
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(20))
                .onErrorResume(e -> Mono.just("[]"))
                .block();

            List<WaybackUrl> urls = parseCdx(body);
            log.info("Wayback CDX found {} URLs for {}", urls.size(), domain);
            return new WaybackResult(domain, urls);

        } catch (Exception e) {
            log.warn("Wayback CDX failed for {}: {}", domain, e.getMessage());
            return new WaybackResult(domain, List.of());
        }
    }

    private List<WaybackUrl> parseCdx(String json) {
        List<WaybackUrl> result = new ArrayList<>();
        try {
            // CDX returns array of arrays; first row is headers
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            JsonNode arr = mapper.readTree(json);
            if (!arr.isArray() || arr.size() < 2) return result;
            // Skip header row
            Set<String> seen = new LinkedHashSet<>();
            for (int i = 1; i < arr.size(); i++) {
                JsonNode row = arr.get(i);
                if (row.size() < 4) continue;
                String url       = row.get(0).asText();
                String status    = row.get(1).asText();
                String mime      = row.get(2).asText();
                String timestamp = row.get(3).asText();
                if (seen.add(url)) {
                    result.add(new WaybackUrl(url, status, mime, timestamp));
                }
            }
        } catch (Exception e) {
            log.debug("CDX parse error: {}", e.getMessage());
        }
        return result;
    }
}