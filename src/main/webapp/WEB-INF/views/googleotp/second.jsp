<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page session="false" %>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%> 

<html>
<head>
	<title>Google OTP 2차 인증 try</title>
	<script>
	if('${result}' !='') {
		alert('${result}');
	}
	</script>
</head>
<body>
<h1>
	1차 인증 OK <br/>
	2차 인증 Try  
</h1>
 <form name="f" method="post" action="third">
<P>  secretKey <input type="text" name="secretKey" value="${secretKey}"/></P>
<P>  barcode url : <img src="${url}"/></P>
<P>  input otp : <input type="text" name="user_code"/></P>
<P>  <input type="submit" name="확인"/></P>
</form>
</body>
</html>
