package saml.service.provider.web;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;


@Controller
@RequiredArgsConstructor
public class ServiceProviderController {
    private static final Logger log = LoggerFactory.getLogger(ServiceProviderController.class);

    final Saml2RelyingPartyProperties saml2RelyingPartyProperties;
    final RelyingPartyRegistrationRepository idpRepo;

    @GetMapping("/initiateSSO")
    public void initiateSSO(HttpServletRequest request, HttpServletResponse response,
                            @RequestParam("RelayState") String relayState) throws IOException {
        String contextPath = request.getContextPath();
        // Redirect to IdP with RelayState
        response.sendRedirect(contextPath+"/saml2/authenticate/ibeam?RelayState="+relayState);
    }

    @GetMapping("/idps")
    public String listIDPs(Model model) {
        List<Provider> idpUrlMap = getIdentityProviderUrlMap();
        model.addAttribute("idps", idpUrlMap);
        return "idp-list";
    }

    @RequestMapping(value = {"/", "/index", "/logged-in"})
    public String home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, HttpServletRequest req) {
        //TODO: somehow the attributes and relayParameter is not coming along
        log.info("Got Relay State {}", req.getParameter("RelayState"));
        log.info("Sample SP Application - You are logged in!, attributes: {}", principal.getAttributes());
        return "logged-in";
    }

    @RequestMapping(value = {"/saml/sp/logout-response"})
    public String loggedOut() {
        log.info("Logged out");
        return "logout-response";
    }

    @RequestMapping(value = {"/saml/sp/logout"})
    public String logoutHandle(HttpServletRequest req) {
        log.info("Got Relay State {}", req.getParameter("RelayState"));
        log.info("Logged out");
        return "redirect:/saml/sp/select";
    }

    @RequestMapping(value = {"/saml/sp/select"})
    public String selectIdp(Model model) {
        log.info("Selecting idp to login");
        List<Provider> idpUrlMap = getIdentityProviderUrlMap();
        model.addAttribute("idps", idpUrlMap);
        return "select-provider";
    }

    private List<Provider> getIdentityProviderUrlMap() {
        List<Provider> idps = new ArrayList<>();
        if (idpRepo instanceof Iterable) {
            Iterable<RelyingPartyRegistration> repo = (Iterable<RelyingPartyRegistration>) idpRepo;
            repo.forEach((p) -> idps.add(new Provider(p.getRegistrationId(), Saml2AuthenticationRequestResolver.DEFAULT_AUTHENTICATION_REQUEST_URI.replace("{registrationId}", p.getRegistrationId()))));
        }
        return idps;
    }

    record Provider(String linkText, String redirect) {
    }
}
