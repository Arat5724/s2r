package dev.s2r.releasehub;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PreviewController {
    @GetMapping(value = "/search/preview", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> preview(@RequestParam(name = "q", required = false, defaultValue = "") String q) {
        return ResponseEntity.ok("<main><h1>ReleaseHub search preview</h1><p>Keyword: " + q + "</p></main>");
    }
}
