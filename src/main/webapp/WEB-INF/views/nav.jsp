<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page pageEncoding="utf-8" %>


<nav>


    <ul class="nav justify-content-center">

        <c:if test="${empty connectedUser && !request.requestURI.contains('/login')} ">
            <li class="nav-item">
                <a class="btn btn-primary" href='<c:url value="/login"/>'>Se connecter</a>
            </li>
        </c:if>

        <c:if test="${not empty connectedUser}">
            <li class="nav-item">
                <a class="nav-link" href='<c:url value="/users/list"/>'>Liste des utilisateurs</a>

            </li>
            <li class="nav-item">
                <a class="nav-link" href='<c:url value="/users/create"/>'>Créer un utilisateur</a>
            </li>

        </c:if>
    </ul>


</nav>


