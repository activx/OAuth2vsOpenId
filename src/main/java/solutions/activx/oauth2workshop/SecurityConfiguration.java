package solutions.activx.oauth2workshop;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // включаем аутентификацию для все запросов
        http.authorizeRequests(req -> req.anyRequest().authenticated())
                // Включаем oauth2.0 с настройками по умолчанию
                .oauth2Login(Customizer.withDefaults());
    }

    /**
     * Регистрируем репозиторий клиентов и определяем в нем
     * регистрацию для identity provider'a Auth0
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(
                ClientRegistration.withRegistrationId("my-app")
                        .clientName("Authenticate via Auth0 (java config)")
                        .clientId("oOkANCsoYdGuTutrRYmqoo7hiArxPori")
                        .clientSecret("4qWv5Abed_KvPg7rVYPBRrZocIlqyddECk7EQLgcbnXSI1pvQ9jmJO491JqzNi30")
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .scope("openid", "profile", "email")
                        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")

                        //Параметры провайдера
                        .authorizationUri("https://activx.auth0.com/authorize")
                        .tokenUri("https://activx.auth0.com/oauth/token")
                        .jwkSetUri("https://activx.auth0.com/.well-known/jwks.json")
                        .userInfoUri("https://activx.auth0.com/userinfo")

                        .userNameAttributeName("nickname")
                        .build()
        );
    }

    /**
     * Добавляем аксесс токен в исходящие запросы
     * @param clientService отвечает за получение агрегации между access/refresh token и
     *                    client registration аутентифицированного пользователя
     */
    @Bean
    public RestTemplate restTemplate(OAuth2AuthorizedClientService clientService) {
        // Добавляем интерцептор в рест темплейт
        return new RestTemplateBuilder().interceptors((request, bytes, execution) -> {
            // Достаем текущий объект аутентификации
            var auth = ((OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication());

            // Достаем агрегацию client registration и access token
            var authorizedClient = clientService.loadAuthorizedClient(auth.getAuthorizedClientRegistrationId(), auth.getName());

            //Добавляем токен в хедеры
            request.getHeaders().add(HttpHeaders.AUTHORIZATION, "Bearer ".concat(authorizedClient.getAccessToken().getTokenValue()));

            return execution.execute(request, bytes);
        }).build();
    }
}
