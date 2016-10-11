<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>HTTP Splitting</title>
</head>
<body>
$string = request.getContextPath();
$new_string = filter_var($string, FILTER_SANITIZE_STRING);
    
<% response.sendRedirect($new_string + "/attack?" +
 		        "Screen=" + filter_var(request.getParameter("Screen")) +
 		        "&menu=" + filter_var(request.getParameter("menu")) +
 		        "&fromRedirect=yes&language=" + filter_var(request.getParameter("language"))); 
%>
</body>
</html>
