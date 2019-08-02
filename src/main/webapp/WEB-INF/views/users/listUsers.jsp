<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page pageEncoding="utf-8" %>


<c:import url="/WEB-INF/views/head.jsp"/>

<h2>Liste des utilisateurs</h2>

<table class="table">
    <thead>
    <tr>
        <th>id</th>
        <th>prenom</th>
        <th>nom</th>
        <th>login</th>
    </tr>
    </thead>
    <tbody>

    <c:forEach items="${users}" var="user">
        <tr>
            <td>${user.id}</td>
            <td>${user.firstname}</td>
            <td>${user.lastname}</td>
            <td>${user.login}</td>
        </tr>
    </c:forEach>
    </tbody>
</table>

<c:import url="/WEB-INF/views/foot.jsp"/>

