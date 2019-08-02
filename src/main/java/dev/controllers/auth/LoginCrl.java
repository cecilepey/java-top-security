package dev.controllers.auth;

import java.io.IOException;
import java.util.Base64;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

import dev.domains.User;
import dev.services.LoginService;
import dev.services.ServicesFactory;

@WebServlet("/login")
public class LoginCrl extends HttpServlet {

	private LoginService loginService = ServicesFactory.LOGIN_SERVICE;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.getRequestDispatcher("/WEB-INF/views/auth/login.jsp").forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String login = req.getParameter("login");
		String password = req.getParameter("pass");

		Optional<User> userOpt = loginService.connect(login, password);

		if (userOpt.isPresent()) {
			User user = userOpt.get();

			String key = "message top secret";

			String data = user.getFirstname() + "," + user.getLastname() + "," + user.getLogin() + ","
					+ user.getAdmin();

			String dataHashe = Base64.getUrlEncoder().encodeToString(data.getBytes());

			String signature = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmacHex(dataHashe);

			String cookieValue = dataHashe + "." + signature;

			Cookie monCookie = new Cookie("AUTH", cookieValue);
			monCookie.setHttpOnly(true);
			resp.addCookie(monCookie);

			resp.sendRedirect(req.getContextPath() + "/users/list");
		} else {
			req.setAttribute("errors", "les informations fournies sont incorrectes");
			req.getRequestDispatcher("/WEB-INF/views/auth/login.jsp").forward(req, resp);
		}
	}
}
