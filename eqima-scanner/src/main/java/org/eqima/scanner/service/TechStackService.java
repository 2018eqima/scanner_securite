package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class TechStackService {

    private static final Logger log = LoggerFactory.getLogger(TechStackService.class);

    // Versions minimales considérées comme à jour
    private static final Map<String, String> MIN_SAFE = Map.ofEntries(
            Map.entry("nginx",      "1.24.0"),
            Map.entry("apache",     "2.4.58"),
            Map.entry("openssl",    "3.0.0"),
            Map.entry("php",        "8.1.0"),
            Map.entry("python",     "3.11.0"),
            Map.entry("ruby",       "3.2.0"),
            Map.entry("node",       "20.0.0"),
            Map.entry("java",       "17.0.0"),
            Map.entry("jquery",     "3.7.0"),
            Map.entry("bootstrap",  "5.3.0"),
            Map.entry("wordpress",  "6.4.0"),
            Map.entry("drupal",     "10.0.0"),
            Map.entry("joomla",     "4.4.0"),
            Map.entry("laravel",    "10.0.0"),
            Map.entry("django",     "4.2.0"),
            Map.entry("spring",     "6.0.0"),
            Map.entry("react",      "18.0.0"),
            Map.entry("angular",    "17.0.0"),
            Map.entry("vue",        "3.0.0")
    );

    // Header → catégorie
    private static final Map<String, String> HEADER_CATEGORIES = Map.of(
            "server",            "server",
            "x-powered-by",      "language",
            "x-generator",       "cms",
            "x-aspnet-version",  "framework",
            "x-aspnetmvc-version","framework",
            "x-runtime",         "language",
            "x-drupal-cache",    "cms",
            "x-joomla-content",  "cms"
    );

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public TechStackService(WebClient.Builder builder, ObjectMapper objectMapper) {
        this.webClient = builder.build();
        this.objectMapper = objectMapper;
    }

    public String detect(String targetUrl) {
        try {
            String html = fetchPage(targetUrl);
            Map<String, String> headers = fetchHeaders(targetUrl);
            return buildTechData(targetUrl, headers, html);
        } catch (Exception e) {
            log.warn("TechStack detection failed for {}: {}", targetUrl, e.getMessage());
            return null;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────

    private String fetchPage(String url) {
        try {
            return webClient.get().uri(URI.create(url))
                    .header("User-Agent", "EQIMA-Scanner/1.0")
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(15))
                    .block();
        } catch (Exception e) {
            return "";
        }
    }

    private Map<String, String> fetchHeaders(String url) {
        Map<String, String> result = new LinkedHashMap<>();
        try {
            webClient.head().uri(URI.create(url))
                    .header("User-Agent", "EQIMA-Scanner/1.0")
                    .retrieve()
                    .toBodilessEntity()
                    .timeout(Duration.ofSeconds(10))
                    .doOnNext(resp -> resp.getHeaders().forEach((k, v) -> {
                        if (!v.isEmpty()) result.put(k.toLowerCase(), v.get(0));
                    }))
                    .block();
        } catch (Exception e) {
            // Ignore — some servers reject HEAD
        }
        if (result.isEmpty()) {
            // Fallback: GET and capture headers
            try {
                webClient.get().uri(URI.create(url))
                        .header("User-Agent", "EQIMA-Scanner/1.0")
                        .retrieve()
                        .toBodilessEntity()
                        .timeout(Duration.ofSeconds(10))
                        .doOnNext(resp -> resp.getHeaders().forEach((k, v) -> {
                            if (!v.isEmpty()) result.put(k.toLowerCase(), v.get(0));
                        }))
                        .block();
            } catch (Exception ex) { /* ignore */ }
        }
        return result;
    }

    private String buildTechData(String targetUrl, Map<String, String> headers, String html) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();

        // ── Infos de base ──────────────────────────────────────────────────
        root.put("url", targetUrl);
        root.put("host", URI.create(targetUrl).getHost());

        // ── En-têtes bruts (subset utile) ─────────────────────────────────
        ObjectNode rawHeaders = objectMapper.createObjectNode();
        List.of("server","x-powered-by","x-generator","via","content-type",
                "x-aspnet-version","x-aspnetmvc-version","x-runtime",
                "x-frame-options","x-content-type-options","strict-transport-security",
                "content-security-policy","x-xss-protection","referrer-policy")
                .forEach(h -> { if (headers.containsKey(h)) rawHeaders.put(h, headers.get(h)); });
        root.set("headers", rawHeaders);

        // ── Détection des composants ───────────────────────────────────────
        List<Map<String, String>> components = new ArrayList<>();

        // Depuis les headers
        detectFromHeaders(headers, components);

        // Depuis le HTML
        if (html != null && !html.isEmpty()) {
            detectFromHtml(html, components);
        }

        // ── Dédupliquer et catégoriser ─────────────────────────────────────
        List<Map<String, String>> server    = filterByCategory(components, "server");
        List<Map<String, String>> os        = filterByCategory(components, "os");
        List<Map<String, String>> languages = filterByCategory(components, "language");
        List<Map<String, String>> frameworks= filterByCategory(components, "framework");
        List<Map<String, String>> cms       = filterByCategory(components, "cms");
        List<Map<String, String>> libraries = filterByCategory(components, "library");
        List<Map<String, String>> cdn       = filterByCategory(components, "cdn");
        List<Map<String, String>> security  = filterByCategory(components, "security");

        root.set("server",     toJsonArray(server));
        root.set("os",         toJsonArray(os));
        root.set("languages",  toJsonArray(languages));
        root.set("frameworks", toJsonArray(frameworks));
        root.set("cms",        toJsonArray(cms));
        root.set("libraries",  toJsonArray(libraries));
        root.set("cdn",        toJsonArray(cdn));
        root.set("security",   toJsonArray(security));

        // ── Composants obsolètes ───────────────────────────────────────────
        ArrayNode outdated = objectMapper.createArrayNode();
        for (Map<String, String> comp : components) {
            String name    = comp.getOrDefault("name", "").toLowerCase();
            String version = comp.getOrDefault("version", "");
            String minSafe = MIN_SAFE.get(name);
            if (minSafe != null && !version.isEmpty() && isOutdated(version, minSafe)) {
                ObjectNode o = objectMapper.createObjectNode();
                o.put("component", comp.get("name"));
                o.put("detectedVersion", version);
                o.put("minimumSafeVersion", minSafe);
                o.put("status", "OUTDATED");
                outdated.add(o);
            }
        }
        root.set("outdatedComponents", outdated);

        // ── En-têtes de sécurité manquants ────────────────────────────────
        ArrayNode missingSecurity = objectMapper.createArrayNode();
        Map<String, String> secHeaders = Map.of(
            "strict-transport-security", "HSTS manquant — forcer HTTPS",
            "content-security-policy",   "CSP manquant — risque XSS",
            "x-frame-options",           "X-Frame-Options manquant — risque clickjacking",
            "x-content-type-options",    "X-Content-Type-Options manquant",
            "referrer-policy",           "Referrer-Policy manquant"
        );
        secHeaders.forEach((header, msg) -> {
            if (!headers.containsKey(header)) missingSecurity.add(msg);
        });
        root.set("missingSecurityHeaders", missingSecurity);

        return objectMapper.writeValueAsString(root);
    }

    // ─────────────────────────────────────────────────────────────────────────

    private void detectFromHeaders(Map<String, String> headers, List<Map<String, String>> out) {
        String server = headers.get("server");
        if (server != null) {
            parseServerHeader(server, out);
        }

        String poweredBy = headers.get("x-powered-by");
        if (poweredBy != null) {
            Matcher m = Pattern.compile("([\\w.]+)(?:/([\\d.]+))?").matcher(poweredBy);
            if (m.find()) {
                out.add(comp(m.group(1), m.group(2), "language"));
            }
        }

        String generator = headers.get("x-generator");
        if (generator != null) {
            out.add(comp(generator.trim(), null, "cms"));
        }

        String aspNet = headers.get("x-aspnet-version");
        if (aspNet != null) out.add(comp("ASP.NET", aspNet.trim(), "framework"));

        String aspMvc = headers.get("x-aspnetmvc-version");
        if (aspMvc != null) out.add(comp("ASP.NET MVC", aspMvc.trim(), "framework"));

        String runtime = headers.get("x-runtime");
        if (runtime != null) {
            // Ruby on Rails typically sets this
            out.add(comp("Ruby on Rails", null, "framework"));
        }

        String via = headers.get("via");
        if (via != null) {
            if (via.toLowerCase().contains("cloudflare")) out.add(comp("Cloudflare", null, "cdn"));
            if (via.toLowerCase().contains("varnish"))    out.add(comp("Varnish", null, "cdn"));
            if (via.toLowerCase().contains("squid"))      out.add(comp("Squid", null, "cdn"));
        }

        String cf = headers.get("cf-ray");
        if (cf != null) out.add(comp("Cloudflare", null, "cdn"));

        String akamai = headers.get("x-check-cacheable");
        if (akamai != null) out.add(comp("Akamai", null, "cdn"));

        if (headers.containsKey("x-drupal-cache") || headers.containsKey("x-drupal-dynamic-cache")) {
            out.add(comp("Drupal", null, "cms"));
        }
    }

    private void parseServerHeader(String server, List<Map<String, String>> out) {
        // Ex: "nginx/1.18.0", "Apache/2.4.54 (Ubuntu)", "Microsoft-IIS/10.0"
        Pattern p = Pattern.compile("([\\w.-]+)/([\\d.]+)");
        Matcher m = p.matcher(server);
        boolean found = false;
        while (m.find()) {
            String name = m.group(1);
            String version = m.group(2);
            // Ignorer les sous-composants connus non pertinents
            if (name.equalsIgnoreCase("openssl") || name.equalsIgnoreCase("mod_ssl")) {
                out.add(comp(name, version, "security"));
                continue;
            }
            if (name.equalsIgnoreCase("ubuntu") || name.equalsIgnoreCase("debian") ||
                name.equalsIgnoreCase("centos") || name.equalsIgnoreCase("rhel")) {
                out.add(comp(name, version, "os"));
                continue;
            }
            out.add(comp(name, version, found ? "language" : "server"));
            found = true;
        }

        // OS dans le header server: "Apache/2.4.54 (Ubuntu)"
        Matcher osMatcher = Pattern.compile("\\(([^)]+)\\)").matcher(server);
        if (osMatcher.find()) {
            String osInfo = osMatcher.group(1);
            if (!osInfo.isEmpty()) out.add(comp(osInfo.trim(), null, "os"));
        }
    }

    private void detectFromHtml(String html, List<Map<String, String>> out) {
        // Meta generator tag
        Matcher metaGen = Pattern.compile(
                "<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
                Pattern.CASE_INSENSITIVE).matcher(html);
        if (!metaGen.find()) {
            metaGen = Pattern.compile(
                "<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']generator[\"']",
                Pattern.CASE_INSENSITIVE).matcher(html);
        }
        if (metaGen.find()) {
            String gen = metaGen.group(1).trim();
            Matcher versionM = Pattern.compile("([\\w .]+?)\\s+([\\d.]+)").matcher(gen);
            if (versionM.find()) {
                out.add(comp(versionM.group(1).trim(), versionM.group(2), "cms"));
            } else {
                out.add(comp(gen, null, "cms"));
            }
        }

        // jQuery
        Matcher jq = Pattern.compile("jquery[/-]([\\d.]+)", Pattern.CASE_INSENSITIVE).matcher(html);
        if (jq.find()) out.add(comp("jQuery", jq.group(1), "library"));

        // Bootstrap
        Matcher bs = Pattern.compile("bootstrap[/-]([\\d.]+)", Pattern.CASE_INSENSITIVE).matcher(html);
        if (bs.find()) out.add(comp("Bootstrap", bs.group(1), "library"));

        // React
        if (html.contains("__reactFiber") || html.contains("data-reactroot") || html.contains("_reactRootContainer")) {
            out.add(comp("React", null, "framework"));
        }

        // Vue
        if (html.contains("__vue__") || html.contains("data-v-") || html.contains("__VUE__")) {
            out.add(comp("Vue.js", null, "framework"));
        }

        // Angular
        if (html.contains("ng-version") || html.contains("_nghost") || html.contains("ng-app")) {
            Matcher ngv = Pattern.compile("ng-version=\"([\\d.]+)\"").matcher(html);
            out.add(comp("Angular", ngv.find() ? ngv.group(1) : null, "framework"));
        }

        // WordPress
        if (html.contains("/wp-content/") || html.contains("/wp-includes/")) {
            Matcher wpv = Pattern.compile("\\?ver=([\\d.]+)").matcher(html);
            out.add(comp("WordPress", wpv.find() ? wpv.group(1) : null, "cms"));
        }

        // Drupal
        if (html.contains("Drupal.settings") || html.contains("/sites/default/files/")) {
            out.add(comp("Drupal", null, "cms"));
        }

        // Joomla
        if (html.contains("/media/jui/") || html.contains("joomla")) {
            out.add(comp("Joomla", null, "cms"));
        }

        // Laravel
        if (html.contains("laravel_session") || html.contains("XSRF-TOKEN")) {
            out.add(comp("Laravel", null, "framework"));
        }

        // Django
        if (html.contains("csrfmiddlewaretoken") || html.contains("django")) {
            out.add(comp("Django", null, "framework"));
        }

        // Next.js
        if (html.contains("__NEXT_DATA__") || html.contains("_next/static")) {
            out.add(comp("Next.js", null, "framework"));
        }

        // Nuxt
        if (html.contains("__NUXT__") || html.contains("_nuxt/")) {
            out.add(comp("Nuxt.js", null, "framework"));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────

    private Map<String, String> comp(String name, String version, String category) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("name", name);
        if (version != null && !version.isEmpty()) m.put("version", version);
        m.put("category", category);
        return m;
    }

    private List<Map<String, String>> filterByCategory(List<Map<String, String>> all, String cat) {
        // Déduplique par nom
        Map<String, Map<String, String>> seen = new LinkedHashMap<>();
        for (Map<String, String> c : all) {
            if (cat.equals(c.get("category"))) {
                seen.putIfAbsent(c.get("name").toLowerCase(), c);
            }
        }
        return new ArrayList<>(seen.values());
    }

    private ArrayNode toJsonArray(List<Map<String, String>> list) {
        ArrayNode arr = objectMapper.createArrayNode();
        for (Map<String, String> item : list) {
            ObjectNode node = objectMapper.createObjectNode();
            item.forEach(node::put);
            arr.add(node);
        }
        return arr;
    }

    /**
     * Compare deux versions sous forme "major.minor.patch".
     * Retourne true si detected < minimum.
     */
    private boolean isOutdated(String detected, String minimum) {
        try {
            int[] d = parseVersion(detected);
            int[] m = parseVersion(minimum);
            for (int i = 0; i < Math.min(d.length, m.length); i++) {
                if (d[i] < m[i]) return true;
                if (d[i] > m[i]) return false;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private int[] parseVersion(String v) {
        String[] parts = v.replaceAll("[^\\d.]", "").split("\\.");
        int[] nums = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try { nums[i] = Integer.parseInt(parts[i]); } catch (NumberFormatException e) { nums[i] = 0; }
        }
        return nums;
    }
}