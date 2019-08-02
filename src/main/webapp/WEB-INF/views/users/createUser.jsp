<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page pageEncoding="utf-8" %>
<c:import url="/WEB-INF/views/head.jsp"/>

<h2>Créer un utilisateur</h2>

<form method="post">
    <div class="form-group">
        <label> Nom
            <input type="text" name="last" class="form-control">
        </label>
    </div>

    <div class="form-group">
        <label> Prénom
            <input type="text" name="first" class="form-control">
        </label>
    </div>

    <div class="form-group">
        <label> Login
            <input type="text" name="login" class="form-control">
        </label>
    </div>

    <div class="form-group">
        <label> Mot de passe
            <input type="password" name="pass" class="form-control">
        </label>
    </div>

    <c:if test="${not empty param.validationErrors}">
        <div class="alert alert-danger mt-2" role="alert">
            Tentative d'attaque ${param.validationErrors}
        </div>

    </c:if>



    <input type="submit" value="Créer" class="btn btn-primary">
</form>
<c:import url="/WEB-INF/views/foot.jsp"/>