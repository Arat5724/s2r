package dev.s2r.releasehub;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class RedirectController {
    @GetMapping("/go")
    public String go(@RequestParam(name = "next", required = false, defaultValue = "/") String next) {
        return "redirect:" + next;
    }
}
