<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@page pageEncoding="utf-8" %>
<!doctype html>
<html>

<head>
    <title>Top Security</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
          integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
    <script>

        function doIt(first, last, login, pass) {

            fetch('<c:url value="/users/create"/>', { headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                }, method: 'POST', credentials:'same-origin', body: 'last='+ last +'&first='+ first + '&login=' + login + '&pass=' + pass })
                .then();
        }
    </script>
</head>
<body class="container">

<div class="jumbotron">
    <c:if test="${not empty connectedUser}">
        <div class="float-right">
            Bonjour ${connectedUser.firstname} <c:if test="${connectedUser.admin}">(Administrateur)</c:if>
            <form method="post" action='<c:url value="/logout"/>' class="float-right">
                <input type="submit" class="btn btn-danger" value="Se déconnecter">
            </form>
        </div>
    </c:if>

    <h1 class="display-4">Application Top Sécurité</h1>
    <p class="lead">Une application sans faille de sécurité.</p>
    <hr class="my-4">
    <c:import url="/WEB-INF/views/nav.jsp"/>
    <div class="row">

    </div>
</div>



