<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page session="false" %>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%> 

<html>
<head>
	<title>ID PW 인증</title>
	<script>
	if('${result}' !='') {
		alert('${result}');
	}
	</script>
</head>
<body>
<h1>
	1차 ID PW 인증  
</h1>
 <form name="f" method="post" action="second">
<P>  ID <input type="text" name="user_id"/></P>
<P>  PW <input type="password" name="user_pw"/></P>
<P>  e-mail <input type="text" name="email"/></P>
<P>  <input type="submit" name="확인"/></P>
</form>
</body>
</html>
