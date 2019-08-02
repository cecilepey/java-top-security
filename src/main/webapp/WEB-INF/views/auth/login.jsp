<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page pageEncoding="utf-8" %>
<c:import url="/WEB-INF/views/head.jsp"/>
<h2>Se connecter</h2>

<form method="post">
    <div class="form-group">
        <label> Nom utilisateur
            <input type="text" name="login" class="form-control">
        </label>
    </div>
    <div class="form-group">
    <label> Mot de passe
        <input type="password" name="pass" class="form-control">
    </label>
    </div>
    <input type="submit" value="Se connecter" class="btn btn-primary">
</form>

<c:if test="${not empty errors}">
    <div class="alert alert-danger mt-2" role="alert">
        Les informations saisies sont incorrectes.
    </div>

</c:if>

<c:if test="${not empty param.validationErrors}">
    <div class="alert alert-danger mt-2" role="alert">
        ${param.validationErrors}
    </div>

</c:if>



<c:import url="/WEB-INF/views/foot.jsp"/>