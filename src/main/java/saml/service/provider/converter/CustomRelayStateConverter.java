package saml.service.provider.converter;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;

public class CustomRelayStateConverter implements Converter<HttpServletRequest, String> {

    private static final Logger log = LoggerFactory.getLogger(CustomRelayStateConverter.class);

    @Override
    public String convert(HttpServletRequest request) {
        String relayState = request.getParameter("RelayState");
        log.info("relay state parameter in converter "+ relayState);
        return relayState;
    }
}