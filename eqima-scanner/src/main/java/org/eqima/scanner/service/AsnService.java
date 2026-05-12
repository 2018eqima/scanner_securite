package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Service
public class AsnService {

    private static final Logger log = LoggerFactory.getLogger(AsnService.class);

    private final WebClient bgpView = WebClient.builder()
        .baseUrl("https://api.bgpview.io")
        .defaultHeader("User-Agent", "EqimaScanner/1.0")
        .build();

    public record AsnResult(String ip, String asn, String asnName, String countryCode, List<String> prefixes) {}

    /** Lookup ASN for a given IP then retrieve all prefixes announced by that ASN */
    public AsnResult lookup(String ip) {
        try {
            // Step 1: IP → ASN
            JsonNode ipInfo = bgpView.get()
                .uri("/ip/{ip}", ip)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .timeout(Duration.ofSeconds(10))
                .onErrorResume(e -> Mono.empty())
                .block();

            if (ipInfo == null) return new AsnResult(ip, null, null, null, List.of());

            JsonNode asns = ipInfo.path("data").path("prefixes");
            String asn = null, asnName = null, country = null;
            if (asns.isArray() && asns.size() > 0) {
                JsonNode first = asns.get(0);
                asn = first.path("asn").path("asn").asText(null);
                asnName = first.path("asn").path("name").asText(null);
                country = first.path("asn").path("country_code").asText(null);
            }

            if (asn == null) return new AsnResult(ip, null, null, null, List.of());

            // Step 2: ASN → prefixes
            List<String> prefixes = fetchPrefixes(asn);
            log.info("ASN {} ({}) owns {} prefixes", asn, asnName, prefixes.size());
            return new AsnResult(ip, "AS" + asn, asnName, country, prefixes);

        } catch (Exception e) {
            log.warn("ASN lookup failed for {}: {}", ip, e.getMessage());
            return new AsnResult(ip, null, null, null, List.of());
        }
    }

    private List<String> fetchPrefixes(String asn) {
        try {
            JsonNode data = bgpView.get()
                .uri("/asn/{asn}/prefixes", asn)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .timeout(Duration.ofSeconds(10))
                .onErrorResume(e -> Mono.empty())
                .block();

            List<String> result = new ArrayList<>();
            if (data != null) {
                JsonNode v4 = data.path("data").path("ipv4_prefixes");
                if (v4.isArray()) v4.forEach(p -> result.add(p.path("prefix").asText()));
            }
            return result;
        } catch (Exception e) {
            return List.of();
        }
    }

    /** Resolve domain to IP then do ASN lookup */
    public AsnResult lookupDomain(String domain) {
        try {
            String ip = InetAddress.getByName(domain).getHostAddress();
            return lookup(ip);
        } catch (Exception e) {
            log.debug("Cannot resolve {} for ASN lookup: {}", domain, e.getMessage());
            return new AsnResult(domain, null, null, null, List.of());
        }
    }
}