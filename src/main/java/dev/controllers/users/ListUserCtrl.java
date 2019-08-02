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
import java.util.List;

@WebServlet("/users/list")
public class ListUserCtrl extends HttpServlet {

    private UserService userService = ServicesFactory.USER_SERVICE;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        List<User> users = this.userService.list();

        req.setAttribute("users", users);

        req.getRequestDispatcher("/WEB-INF/views/users/listUsers.jsp").forward(req, resp);
    }


}
