package saml.service.provider.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class SamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private static final Logger log = LoggerFactory.getLogger(SamlAuthenticationSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        // Extract RelayState
        String relayState = request.getParameter("RelayState");
        log.info("relay state from saml response "+relayState);
        String contextPath = request.getContextPath();
        String samlResponse = request.getParameter("SAMLResponse");
        /* enable if we want to debug saml response
        if (samlResponse != null) {
            log.info("SAML Response before : " + samlResponse);
           // Decode and log the SAML response (for debugging purposes only, do not log sensitive information in production)
            byte[] decodedBytes = java.util.Base64.getDecoder().decode(samlResponse);
            String decodedSamlResponse = new String(decodedBytes, java.nio.charset.StandardCharsets.UTF_8);
            log.info("SAML Response: " + decodedSamlResponse);
        } */
        // Perform custom actions with the SAML response, if needed
        if (relayState != null && !relayState.isEmpty()) {
            // Redirect to the RelayState URL
            assert samlResponse != null;
            // Build an HTML form with auto-submit
            String htmlResponse = "<html>" +
                    "<body onload='document.forms[0].submit()'>" +
                    "<form action='" + relayState + "' method='POST'>" +
                    "<input type='hidden' name='SAMLResponse' value='" + samlResponse + "' />" +
                    "<input type='hidden' name='RelayState' value='" + relayState + "' />" +
                    "</form>" +
                    "</body>" +
                    "</html>";

            // Set content type and write the response
            response.setContentType("text/html");
            response.getWriter().write(htmlResponse);
            return;
        }
         // Fallback to a default URL if RelayState is not present
         response.sendRedirect(contextPath+"/logged-in");

    }

}
