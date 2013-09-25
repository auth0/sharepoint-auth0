<!DOCTYPE html>
<html lang="en">
	<head>
		<title>SharePoint Login</title>
		<meta charset="UTF-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<meta name="apple-mobile-web-app-capable" content="yes" />
		<style type="text/css">
			.signin {
				position: absolute;
				top: 50%;
				left: 50%;
				width: 400px;
				height: 530px;
				margin-left: -200px;
				margin-top: -265px;
			}

			.signin .auth0 {
				height: 450px;
			}

			.signin .windows {
				font-family: sans-serif;
				text-align: center;
				margin: 20px auto;
				color: rgb(109, 109, 109);
			}

			.signin .windows a {
				color: rgb(109, 109, 109);
				font-weight: bold;
			}
		</style>
	</head>
	<body> 
	<div class="signin">
		<div class="windows">
			Sign In using <a id="windows-signin-link" href="#">Windows Authentication</a> or...
		</div>
		<div class="auth0" id="auth0-signin"></div>
	</div>
	<script type="text/javascript">
		function getParameterByName(name) {
			name = name.replace(/[\[]/, "\\\[").replace(/[\]]/, "\\\]");
			var regexS = "[\\?&]" + name + "=([^&#]*)";
			var regex = new RegExp(regexS);
			var results = regex.exec(window.location.search);
			if (results == null)
				return "";
			else
				return decodeURIComponent(results[1].replace(/\+/g, " "));
		}
		
		(function() {
			var a0 = document.createElement('script'); a0.type = 'text/javascript';
			a0.src = 'https://sdk.auth0.com/auth0.js#client=REPLACE_WITH_CLIENT_ID&protocol=wsfed&container=auth0-signin&state=' + getParameterByName('Source');
			var s = document.getElementsByTagName('script')[0];
			s.parentNode.insertBefore(a0, s);
		})();
	</script>
	<script type="text/javascript">
		window.onload = function () {
			window.Auth0.ready(function() {
				window.Auth0.signIn({ onestep: true, theme: 'static', standalone: true });
			});
			
			document.getElementById('windows-signin-link').href = '/_windows/default.aspx?ReturnUrl=/_layouts/Authenticate.aspx?Source=%2F&Source=' + getParameterByName('Source');
		}
	</script>
  </body>
</html>
