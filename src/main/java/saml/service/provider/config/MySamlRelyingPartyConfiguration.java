package saml.service.provider.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import saml.service.provider.handler.SamlAuthenticationSuccessHandler;
import saml.service.provider.converter.CustomRelayStateConverter;

@Configuration(proxyBeanMethods = false)
public class MySamlRelyingPartyConfiguration {
    private static final String[] AUTH_WHITELIST = {
            "/swagger-resources/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/v3/api-docs/**",
            "/h2-console/**",
            "/webjars/**",
            "/favicon.ico",
            "/static/**",
            "/signup/**",
            "/error/**",
            "/public/**",
            "/saml/**",
            "initiateSSO/**",
            "/login/saml2/sso/ibeam/**",
            "/relaystate-redirect/**"
    };

    CustomRelayStateConverter customRelayStateConverter = new CustomRelayStateConverter();

    @Bean
    Saml2AuthenticationRequestResolver resolver(RelyingPartyRegistrationRepository repo) {
        OpenSaml4AuthenticationRequestResolver openSaml4AuthenticationRequestResolver =
                new OpenSaml4AuthenticationRequestResolver(repo);
        openSaml4AuthenticationRequestResolver.setRelayStateResolver(customRelayStateConverter);
        return openSaml4AuthenticationRequestResolver;
    }

    @Bean
    public AuthenticationSuccessHandler customSuccessHandler() {
        return new SamlAuthenticationSuccessHandler();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   Saml2AuthenticationRequestResolver samlAuthReqResolver) throws Exception {
        http.authorizeHttpRequests(ah -> ah
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers(AUTH_WHITELIST).permitAll()
                .anyRequest().authenticated());
                //.requestMatchers(AUTH_SSO_LIST).authenticated()); //this one will catch the rest of the patterns

        http.saml2Login(saml2 -> saml2.authenticationRequestResolver(samlAuthReqResolver)
                .successHandler(customSuccessHandler()));

        http.saml2Login(saml2 -> saml2.loginProcessingUrl("/login/saml2/sso/ibeam/"));
        http.saml2Logout(saml2 -> saml2
                .logoutUrl("/saml/sp/logout") //mvc post url
                .logoutRequest(req -> req.logoutUrl("/saml/sp/logout"))
                .logoutResponse(resp -> resp.logoutUrl("/saml/sp/logout-response"))
        );
        http.formLogin(login -> login.loginPage("/saml/sp/select"));
        http.saml2Metadata(saml2 -> saml2.metadataUrl("/saml/metadata"));
        return http.build();
    }

}
