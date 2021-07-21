package solutions.activx.oauth2workshop;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class HomeController {
    private final RestTemplate restTemplate;


    @GetMapping
    public String mainPage(Authentication principal) {
        return "<h1>Welcome, " + principal.getName() + "</h1>";
    }

    @GetMapping("/auth")
    public Authentication getAuthentication(Authentication authentication) {
        return authentication;
    }

    /**
     * @param authorizedClient с помощью аннотации {@link RegisteredOAuth2AuthorizedClient } мы достаем authorizedClient
     *                         что по сути является агрегацией {@link ClientRegistration } и {@link OAuth2AccessToken}
     *                         указав при этом registration id "my-app"
     */
    @GetMapping("/external")
    public Map getExternal(@RegisteredOAuth2AuthorizedClient("my-app") OAuth2AuthorizedClient authorizedClient) {
        var uri = authorizedClient
                .getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUri();
        return restTemplate.getForObject(uri, Map.class);
    }
}
