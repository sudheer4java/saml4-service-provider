package saml.service.provider.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import java.io.IOException;

public class SamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private static final Logger log = LoggerFactory.getLogger(SamlAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        // Extract RelayState
        String relayState = request.getParameter("RelayState");
        log.info("relay state from saml response "+relayState);
        String contextPath = request.getContextPath();
        // Redirect to the URL stored in RelayState
        if (relayState != null && !relayState.isEmpty()) {
            response.sendRedirect(contextPath+"/logged-in");
            //response.sendRedirect(relayState);
        } else {
            response.sendRedirect(contextPath+"/logged-in");
        }
    }
    private void isValidURi(String relay){
    }

}
