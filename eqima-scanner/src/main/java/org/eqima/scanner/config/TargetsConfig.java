package org.eqima.scanner.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
@ConfigurationProperties(prefix = "eqima")
public class TargetsConfig {

    private List<Target> targets = new ArrayList<>();

    public List<Target> getTargets() { return targets; }
    public void setTargets(List<Target> targets) { this.targets = targets; }

    public Optional<Target> findById(String id) {
        return targets.stream().filter(t -> t.getId().equals(id)).findFirst();
    }

    public static class Target {
        private String id;
        private String name;
        private String icon;
        private List<String> urls = new ArrayList<>();
        private List<String> modules = new ArrayList<>();

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public String getIcon() { return icon; }
        public void setIcon(String icon) { this.icon = icon; }

        public List<String> getUrls() { return urls; }
        public void setUrls(List<String> urls) { this.urls = urls; }

        public List<String> getModules() { return modules; }
        public void setModules(List<String> modules) { this.modules = modules; }
    }
}