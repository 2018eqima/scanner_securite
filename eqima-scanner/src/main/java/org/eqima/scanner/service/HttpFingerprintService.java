package org.eqima.scanner.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.*;

@Service
public class HttpFingerprintService {

    private static final Logger log = LoggerFactory.getLogger(HttpFingerprintService.class);

    private final WebClient client = WebClient.builder()
        .defaultHeader("User-Agent", "Mozilla/5.0 (compatible; EqimaScanner/1.0)")
        .codecs(c -> c.defaultCodecs().maxInMemorySize(512 * 1024))
        .build();

    // Security headers to check
    private static final List<String> SEC_HEADERS = List.of(
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection"
    );

    // Sensitive paths to probe
    private static final List<String> SENSITIVE_PATHS = List.of(
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/HEAD", "/.git/config",
        "/config.js", "/config.json", "/settings.json",
        "/backup.zip", "/backup.tar.gz", "/dump.sql",
        "/api/swagger.json", "/swagger.json", "/openapi.json", "/openapi.yaml",
        "/swagger-ui/", "/swagger-ui.html", "/redoc/",
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
        "/phpinfo.php", "/info.php", "/adminer.php", "/phpmyadmin/",
        "/.DS_Store", "/web.config", "/crossdomain.xml", "/robots.txt",
        "/sitemap.xml", "/.htaccess",
        "/graphql", "/graphiql", "/__graphql",
        "/api/v1/users", "/api/v2/users", "/api/users",
        "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
        "/.well-known/security.txt", "/security.txt"
    );

    // Tech fingerprints: header/value patterns
    private static final Map<String, String> TECH_PATTERNS = Map.ofEntries(
        Map.entry("X-Powered-By:PHP", "PHP"),
        Map.entry("X-Powered-By:ASP.NET", "ASP.NET"),
        Map.entry("X-Powered-By:Express", "Node.js/Express"),
        Map.entry("Server:nginx", "Nginx"),
        Map.entry("Server:Apache", "Apache"),
        Map.entry("Server:Microsoft-IIS", "IIS"),
        Map.entry("Server:Tomcat", "Tomcat"),
        Map.entry("Server:Jetty", "Jetty"),
        Map.entry("Server:openresty", "OpenResty"),
        Map.entry("X-Generator:WordPress", "WordPress"),
        Map.entry("X-Drupal-Cache", "Drupal"),
        Map.entry("X-Joomla-Response", "Joomla"),
        Map.entry("Set-Cookie:PHPSESSID", "PHP Session"),
        Map.entry("Set-Cookie:JSESSIONID", "Java/Spring Session"),
        Map.entry("Set-Cookie:ASP.NET_SessionId", "ASP.NET Session"),
        Map.entry("Set-Cookie:laravel_session", "Laravel"),
        Map.entry("Set-Cookie:django", "Django"),
        Map.entry("Via:1.1 cloudflare", "Cloudflare"),
        Map.entry("CF-Cache-Status", "Cloudflare"),
        Map.entry("X-Varnish", "Varnish Cache"),
        Map.entry("X-Cache:HIT", "CDN Cache"),
        Map.entry("X-Amzn-Trace-Id", "AWS"),
        Map.entry("X-GUploader", "Google Cloud")
    );

    public record HeaderResult(
        String url,
        int statusCode,
        Map<String, String> headers,
        List<String> missingSecHeaders,
        List<String> technologies,
        List<String> cookieIssues,
        String serverBanner,
        boolean redirectsToHttps
    ) {}

    public record SensitiveFile(String path, int status, String snippet) {}

    public record FingerprintResult(HeaderResult headers, List<SensitiveFile> sensitiveFiles) {}

    public FingerprintResult fingerprint(String baseUrl) {
        HeaderResult headers = probeHeaders(baseUrl);
        List<SensitiveFile> sensitive = probeSensitiveFiles(baseUrl);
        return new FingerprintResult(headers, sensitive);
    }

    private HeaderResult probeHeaders(String url) {
        try {
            // Use exchange to capture headers even on 3xx/4xx/5xx
            final Map<String, String>[] headersRef = new Map[]{new LinkedHashMap<>()};
            final int[] statusRef = {0};
            final boolean[] httpsRedirect = {false};

            client.get()
                .uri(url)
                .exchangeToMono(resp -> {
                    statusRef[0] = resp.statusCode().value();
                    HttpHeaders h = resp.headers().asHttpHeaders();
                    h.forEach((k, v) -> headersRef[0].put(k, String.join(", ", v)));

                    // Check redirect to HTTPS
                    if (url.startsWith("http://") && resp.statusCode().is3xxRedirection()) {
                        String loc = h.getFirst("Location");
                        if (loc != null && loc.startsWith("https://")) httpsRedirect[0] = true;
                    }
                    return resp.bodyToMono(String.class).onErrorReturn("");
                })
                .timeout(Duration.ofSeconds(10))
                .onErrorReturn("")
                .block();

            Map<String, String> headers = headersRef[0];

            // Missing security headers
            List<String> missing = new ArrayList<>();
            for (String h : SEC_HEADERS) {
                boolean found = headers.keySet().stream()
                    .anyMatch(k -> k.equalsIgnoreCase(h));
                if (!found) missing.add(h);
            }

            // Technologies
            List<String> techs = new ArrayList<>();
            headers.forEach((k, v) -> {
                for (Map.Entry<String, String> pattern : TECH_PATTERNS.entrySet()) {
                    String[] parts = pattern.getKey().split(":", 2);
                    if (k.equalsIgnoreCase(parts[0])) {
                        if (parts.length == 1 || v.toLowerCase().contains(parts[1].toLowerCase())) {
                            if (!techs.contains(pattern.getValue())) techs.add(pattern.getValue());
                        }
                    }
                }
            });

            // Cookie issues
            List<String> cookieIssues = new ArrayList<>();
            headers.forEach((k, v) -> {
                if (k.equalsIgnoreCase("Set-Cookie")) {
                    String lower = v.toLowerCase();
                    if (!lower.contains("httponly"))  cookieIssues.add("Missing HttpOnly on: " + v.split(";")[0]);
                    if (!lower.contains("samesite"))  cookieIssues.add("Missing SameSite on: " + v.split(";")[0]);
                    if (!url.startsWith("http://") && !lower.contains("secure"))
                        cookieIssues.add("Missing Secure flag on: " + v.split(";")[0]);
                }
            });

            String server = headers.entrySet().stream()
                .filter(e -> e.getKey().equalsIgnoreCase("Server") || e.getKey().equalsIgnoreCase("X-Powered-By"))
                .map(e -> e.getKey() + ": " + e.getValue())
                .findFirst().orElse(null);

            return new HeaderResult(url, statusRef[0], headers, missing, techs, cookieIssues, server, httpsRedirect[0]);
        } catch (Exception e) {
            log.debug("HTTP fingerprint failed for {}: {}", url, e.getMessage());
            return new HeaderResult(url, 0, Map.of(), SEC_HEADERS, List.of(), List.of(), null, false);
        }
    }

    private List<SensitiveFile> probeSensitiveFiles(String baseUrl) {
        // Strip trailing slash
        String base = baseUrl.replaceAll("/$", "");
        List<SensitiveFile> found = new ArrayList<>();

        for (String path : SENSITIVE_PATHS) {
            try {
                String fullUrl = base + path;
                final int[] status = {0};
                final String[] body = {""};

                client.get()
                    .uri(fullUrl)
                    .exchangeToMono(resp -> {
                        status[0] = resp.statusCode().value();
                        if (resp.statusCode().is2xxSuccessful()) {
                            return resp.bodyToMono(String.class)
                                .timeout(Duration.ofSeconds(5))
                                .onErrorReturn("");
                        }
                        return resp.bodyToMono(Void.class).thenReturn("");
                    })
                    .timeout(Duration.ofSeconds(8))
                    .onErrorReturn("")
                    .block();

                // Report 200, 401, 403 as interesting (resource exists)
                if (status[0] == 200 || status[0] == 401 || status[0] == 403) {
                    // Capture full content for .env and config files, short snippet otherwise
                    boolean isHighValue = path.contains(".env") || path.contains("config")
                        || path.contains(".git") || path.contains("actuator")
                        || path.contains("swagger") || path.contains("openapi")
                        || path.contains("dump") || path.contains("backup");
                    int limit = isHighValue ? 3000 : 200;
                    String snippet = body[0].length() > limit ? body[0].substring(0, limit) + "\n…[tronqué]" : body[0];
                    found.add(new SensitiveFile(path, status[0], snippet));
                    log.info("Sensitive file found: {} → HTTP {} ({} chars)", fullUrl, status[0], snippet.length());
                }
            } catch (Exception ignored) {}
        }
        return found;
    }
}