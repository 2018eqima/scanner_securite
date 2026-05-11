package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/**
 * Intégration OpenVAS/GVM via le protocole GMP (XML over TCP/Unix socket).
 * Se connecte au gvmd via son socket Unix ou TCP.
 */
@Service
public class OpenVasService {

    private static final Logger log = LoggerFactory.getLogger(OpenVasService.class);

    @Value("${openvas.host:127.0.0.1}")
    private String gvmdHost;

    @Value("${openvas.port:9390}")
    private int gvmdPort;

    @Value("${openvas.user:admin}")
    private String gvmdUser;

    @Value("${openvas.password:admin}")
    private String gvmdPassword;

    private final ObjectMapper objectMapper;

    public OpenVasService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /** Vérifie si GVM est accessible et retourne la version */
    public Mono<ObjectNode> getStatus() {
        return Mono.fromCallable(() -> {
            ObjectNode result = objectMapper.createObjectNode();
            try {
                String version = sendGmpCommand("<get_version/>");
                DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                Document doc = db.parse(new ByteArrayInputStream(version.getBytes(StandardCharsets.UTF_8)));
                String ver = doc.getElementsByTagName("version").item(0) != null
                        ? doc.getElementsByTagName("version").item(0).getTextContent() : "unknown";
                result.put("available", true);
                result.put("version", ver);
                result.put("host", gvmdHost);
                result.put("port", gvmdPort);
            } catch (Exception e) {
                result.put("available", false);
                result.put("error", e.getMessage());
            }
            return result;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /** Liste les tâches de scan */
    public Mono<JsonNode> getTasks() {
        return Mono.fromCallable(() -> {
            String xml = sendAuthenticated("<get_tasks/>");
            return parseTasksXml(xml);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /** Crée et lance un scan sur une cible */
    public Mono<ObjectNode> startScan(String target, String name) {
        return Mono.fromCallable(() -> {
            // 1. Créer la cible
            String targetXml = sendAuthenticated(String.format(
                    "<create_target><name>%s</name><hosts>%s</hosts>" +
                    "<port_range>T:1-1024,U:1-1024</port_range></create_target>",
                    escapeXml(name), escapeXml(target)));
            String targetId = extractAttribute(targetXml, "id");

            // 2. Récupérer la config "Full and fast"
            String configs = sendAuthenticated("<get_configs/>");
            String configId = extractConfigId(configs, "Full and fast");

            // 3. Créer la tâche
            String taskXml = sendAuthenticated(String.format(
                    "<create_task><name>%s</name><config id=\"%s\"/><target id=\"%s\"/></create_task>",
                    escapeXml(name), configId, targetId));
            String taskId = extractAttribute(taskXml, "id");

            // 4. Lancer la tâche
            sendAuthenticated(String.format("<start_task task_id=\"%s\"/>", taskId));

            ObjectNode result = objectMapper.createObjectNode();
            result.put("taskId", taskId);
            result.put("targetId", targetId);
            result.put("status", "STARTED");
            return result;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /** Récupère les résultats d'une tâche */
    public Mono<JsonNode> getResults(String taskId) {
        return Mono.fromCallable(() -> {
            String xml = sendAuthenticated(String.format(
                    "<get_results task_id=\"%s\"/>", escapeXml(taskId)));
            return parseResultsXml(xml);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ─── Communication GMP ──────────────────────────────────────────────────

    private String sendAuthenticated(String command) throws Exception {
        String authCommand = String.format(
                "<authenticate><credentials><username>%s</username><password>%s</password></credentials></authenticate>",
                escapeXml(gvmdUser), escapeXml(gvmdPassword));
        try (Socket socket = new Socket(gvmdHost, gvmdPort);
             OutputStream out = socket.getOutputStream();
             InputStream in = socket.getInputStream()) {
            socket.setSoTimeout(30000);
            // Send auth, read and discard auth response
            out.write(authCommand.getBytes(StandardCharsets.UTF_8));
            out.flush();
            readGmpResponse(in);
            // Send actual command, return its response
            out.write(command.getBytes(StandardCharsets.UTF_8));
            out.flush();
            return readGmpResponse(in);
        }
    }

    private String sendGmpCommand(String command) throws Exception {
        try (Socket socket = new Socket(gvmdHost, gvmdPort);
             OutputStream out = socket.getOutputStream();
             InputStream in = socket.getInputStream()) {
            socket.setSoTimeout(30000);
            out.write(command.getBytes(StandardCharsets.UTF_8));
            out.flush();
            return readGmpResponse(in);
        }
    }

    private String readGmpResponse(InputStream in) throws Exception {
        StringBuilder resp = new StringBuilder();
        byte[] buf = new byte[65536];
        long start = System.currentTimeMillis();
        while (System.currentTimeMillis() - start < 15000) {
            if (in.available() > 0) {
                int read = in.read(buf);
                if (read == -1) break;
                resp.append(new String(buf, 0, read, StandardCharsets.UTF_8));
                // Check if we have a complete XML document (ends with closing root tag)
                String s = resp.toString().trim();
                if (s.endsWith(">") && isCompleteXml(s)) break;
            } else {
                String s = resp.toString().trim();
                if (s.endsWith(">") && s.length() > 10 && isCompleteXml(s)) break;
                Thread.sleep(50);
            }
        }
        return resp.toString().trim();
    }

    private boolean isCompleteXml(String xml) {
        // Quick heuristic: count open vs close tags of the root element
        if (xml.isEmpty() || !xml.startsWith("<")) return false;
        int firstSpace = xml.indexOf(' ');
        int firstClose = xml.indexOf('>');
        if (firstClose < 0) return false;
        // Self-closing root
        if (xml.charAt(firstClose - 1) == '/') return true;
        String rootTag = xml.substring(1, firstSpace > 0 && firstSpace < firstClose ? firstSpace : firstClose);
        return xml.contains("</" + rootTag + ">");
    }

    // ─── Parsers XML ─────────────────────────────────────────────────────────

    private JsonNode parseTasksXml(String xml) throws Exception {
        ArrayNode tasks = objectMapper.createArrayNode();
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        NodeList taskNodes = doc.getElementsByTagName("task");
        for (int i = 0; i < taskNodes.getLength(); i++) {
            Element task = (Element) taskNodes.item(i);
            ObjectNode t = objectMapper.createObjectNode();
            t.put("id", task.getAttribute("id"));
            t.put("name", getTextContent(task, "name"));
            t.put("status", getTextContent(task, "status"));
            t.put("progress", safeInt(getTextContent(task, "progress")));
            t.put("lastReport", getTextContent(task, "last_report"));
            tasks.add(t);
        }
        return tasks;
    }

    private JsonNode parseResultsXml(String xml) throws Exception {
        ArrayNode results = objectMapper.createArrayNode();
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        NodeList resultNodes = doc.getElementsByTagName("result");
        for (int i = 0; i < resultNodes.getLength(); i++) {
            Element r = (Element) resultNodes.item(i);
            ObjectNode item = objectMapper.createObjectNode();
            item.put("id", r.getAttribute("id"));
            item.put("name", getTextContent(r, "name"));
            item.put("host", getTextContent(r, "host"));
            item.put("port", getTextContent(r, "port"));
            item.put("severity", getTextContent(r, "severity"));
            item.put("threat", getTextContent(r, "threat"));
            item.put("description", getTextContent(r, "description"));
            item.put("nvtOid", getAttrContent(r, "nvt", "oid"));
            results.add(item);
        }
        return results;
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private String extractAttribute(String xml, String attr) throws Exception {
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        Element root = doc.getDocumentElement();
        // Chercher dans les éléments enfants
        String val = root.getAttribute(attr);
        if (!val.isEmpty()) return val;
        // Chercher dans les éléments avec @id
        NodeList all = root.getChildNodes();
        for (int i = 0; i < all.getLength(); i++) {
            if (all.item(i) instanceof Element e) {
                val = e.getAttribute(attr);
                if (!val.isEmpty()) return val;
            }
        }
        return "";
    }

    private String extractConfigId(String xml, String configName) throws Exception {
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        NodeList configs = doc.getElementsByTagName("config");
        for (int i = 0; i < configs.getLength(); i++) {
            Element c = (Element) configs.item(i);
            String name = getTextContent(c, "name");
            if (name.contains(configName)) return c.getAttribute("id");
        }
        return configs.getLength() > 0 ? ((Element) configs.item(0)).getAttribute("id") : "";
    }

    private String getTextContent(Element parent, String tag) {
        NodeList nl = parent.getElementsByTagName(tag);
        return nl.getLength() > 0 ? nl.item(0).getTextContent().trim() : "";
    }

    private String getAttrContent(Element parent, String tag, String attr) {
        NodeList nl = parent.getElementsByTagName(tag);
        return nl.getLength() > 0 ? ((Element) nl.item(0)).getAttribute(attr) : "";
    }

    private int safeInt(String s) {
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return 0; }
    }

    private String escapeXml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }
}