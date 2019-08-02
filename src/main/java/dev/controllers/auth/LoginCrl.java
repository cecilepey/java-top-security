package dev.controllers.auth;

import dev.domains.User;
import dev.services.LoginService;
import dev.services.ServicesFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

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
            req.getSession().setAttribute("connectedUser", user);
            resp.sendRedirect("/users/list");
        } else {
            req.setAttribute("errors", "les informations fournies sont incorrectes");
            req.getRequestDispatcher("/WEB-INF/views/auth/login.jsp").forward(req, resp);
        }
    }
}
