package solutions.activx.oauth2workshop;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    @GetMapping
    public String mainPage(Authentication principal) {
        return "<h1>Welcome, " + principal.getName() + "</h1>";
    }

    @GetMapping("/auth")
    public Authentication getAuthentication(Authentication authentication){
        return authentication;
    }
}
