package dev.filters;

import java.io.IOException;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

import dev.domains.User;

@WebFilter("/top/*")
public class AuthFilter implements Filter {
	String key = "message top secret";

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) servletRequest;
		HttpServletResponse resp = (HttpServletResponse) servletResponse;

		User connectedUser = null;

		Cookie[] listeDeCookies = req.getCookies();

		if (listeDeCookies != null) {

			for (Cookie unCookie : listeDeCookies) {

				if (unCookie.getName().equals("AUTH")) {

					String dataHasheEtSignature = unCookie.getValue();

					String[] split = dataHasheEtSignature.split("\\.");
					String dataHashe = split[0];
					String signatureRequete = split[1];

					String signature = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmacHex(dataHashe);

					if (signature.equals(signatureRequete)) {
						// ok
						String data = new String(Base64.getUrlDecoder().decode(dataHashe));

						String[] dataSplit = data.split(",");

						connectedUser = new User();
						connectedUser.setFirstname(dataSplit[0]);
						connectedUser.setLastname(dataSplit[1]);
						connectedUser.setLogin(dataSplit[2]);
						connectedUser.setAdmin(new Boolean(dataSplit[3]));

						req.setAttribute("connectedUser", connectedUser);

					}
				}
			}
		}

		if (connectedUser != null || req.getRequestURI().contains("/login")) {
			filterChain.doFilter(servletRequest, servletResponse);
		} else {
			resp.sendRedirect(req.getContextPath() + "/login");
		}

	}

	@Override
	public void destroy() {

	}
}
