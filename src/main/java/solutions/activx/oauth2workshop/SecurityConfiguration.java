package solutions.activx.oauth2workshop;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.web.client.RestTemplate;

import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // включаем аутентификацию для все запросов
        http.authorizeRequests(req -> req
                .mvcMatchers("/create").hasAuthority("CREATE_MESSAGE")
                .mvcMatchers("/delete").hasAuthority("DELETE_MESSAGE")
                .mvcMatchers("/manage").hasAuthority("MANAGE_MESSAGE")
                .anyRequest()
                .authenticated()
        )
                // Включаем oauth2.0 с настройками по умолчанию
                .oauth2Login(oauth2 -> oauth2.userInfoEndpoint()
                        //Добавляем мапер
                        .userAuthoritiesMapper(grantedAuthoritiesMapper()));
    }


    /**
     * Этот мапер достает дополнительне параметры из ID token'a которые я добавил в Auth0 в Rules
     * Без этого добавления работать не будет
     */
    @Bean
    public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        var authorityFieldName = "http://localhost/authorities";
        var issuer = "https://activx.auth0.com/";

        return authorities -> authorities.stream()
                .filter(OidcUserAuthority.class::isInstance)
                .map(OidcUserAuthority.class::cast)
                .map(OidcUserAuthority::getIdToken)
                .filter(oidcIdToken -> issuer.equals(oidcIdToken.getIssuer().toString()))
                .filter(oidcIdToken -> oidcIdToken.hasClaim(authorityFieldName))
                .flatMap(oidcIdToken -> oidcIdToken.getClaimAsStringList(authorityFieldName).stream())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
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
     *
     * @param clientService отвечает за получение агрегации между access/refresh token и
     *                      client registration аутентифицированного пользователя
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
