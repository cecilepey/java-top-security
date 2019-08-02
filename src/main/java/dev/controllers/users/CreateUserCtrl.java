package dev.controllers.users;

import dev.domains.User;
import dev.services.ServicesFactory;
import dev.services.UserService;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/users/create")
public class CreateUserCtrl extends HttpServlet {

    private UserService userService = ServicesFactory.USER_SERVICE;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.getRequestDispatcher("/WEB-INF/views/users/createUser.jsp").forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        this.userService.save(new User( req.getParameter("first"),  req.getParameter("last"), req.getParameter("login"), req.getParameter("pass")));
        resp.sendRedirect(req.getContextPath() + "/users/list");
    }
}
