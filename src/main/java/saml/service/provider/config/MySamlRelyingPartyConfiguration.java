package saml.service.provider.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

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
    };

    @Bean
    Saml2AuthenticationRequestResolver resolver(RelyingPartyRegistrationRepository repo) {
        return new OpenSaml4AuthenticationRequestResolver(repo);
    }
    /*
    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {

        //Here I read a jks file but you can replace the default type with "PKCS12" for example
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] pwd = "nalle123".toCharArray();
        Resource keystoreRes = new ClassPathResource(certificatePath);
        ks.load(keystoreRes.getInputStream(), pwd);

        //Fetch the private key contained in the jks file
        PrivateKey privateRSAKey = (PrivateKey) ks.getKey("apollo", pwd);

        //Fetch the certificate contained in the jks file
        X509Certificate cert = (X509Certificate) ks.getCertificate("apollo");

        //Give your certificate to spring relying party bean
        RelyingPartyRegistration registration = RelyingPartyRegistrations
                .fromMetadataLocation(idpSiteMetaDataUrl)
                .registrationId("https://idp.ssocircle.com")
                .signingX509Credentials((c) -> c.add(Saml2X509Credential.signing(privateRSAKey, cert)))
                .decryptionX509Credentials((c) -> c.add(Saml2X509Credential.decryption(privateRSAKey, cert)))
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }
*/

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   Saml2AuthenticationRequestResolver samlAuthReqResolver) throws Exception {
        http.authorizeHttpRequests(ah -> ah
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers(AUTH_WHITELIST).permitAll()
                .anyRequest().authenticated()); //this one will catch the rest of the patterns

        http.saml2Login(saml2 -> saml2.authenticationRequestResolver(samlAuthReqResolver));

        http.saml2Login(saml2 -> saml2.loginProcessingUrl("/saml/sso"));
        http.saml2Logout(saml2 -> saml2
                .logoutUrl("/saml/logout") //mvc post url
                .logoutRequest(req -> req.logoutUrl("/saml/logout"))
                .logoutResponse(resp -> resp.logoutUrl("/saml/logout-response"))
        );
        http.formLogin(login -> login.loginPage("/saml/select"));
        http.saml2Metadata(saml2 -> saml2.metadataUrl("/saml/metadata"));
        return http.build();
    }

}
