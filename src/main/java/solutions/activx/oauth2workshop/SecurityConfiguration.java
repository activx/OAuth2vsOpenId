package solutions.activx.oauth2workshop;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(req -> req.anyRequest().authenticated())
                .oauth2Login(Customizer.withDefaults());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        return new InMemoryClientRegistrationRepository(
                ClientRegistration.withRegistrationId("my-app")
                .clientName("Authenticate via Auth0 (java config)")
                .clientId("oOkANCsoYdGuTutrRYmqoo7hiArxPori")
                .clientSecret("4qWv5Abed_KvPg7rVYPBRrZocIlqyddECk7EQLgcbnXSI1pvQ9jmJO491JqzNi30")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .scope("openid","profile","email")
                        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")

                .authorizationUri("https://activx.auth0.com/authorize")
                .tokenUri("https://activx.auth0.com/oauth/token")
                .jwkSetUri("https://activx.auth0.com/.well-known/jwks.json")

                .userNameAttributeName("nickname")
                .build()
        );
    }

}
