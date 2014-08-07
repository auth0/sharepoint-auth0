<!DOCTYPE html>
<html lang="en">
	<head>
		<title>SharePoint Login</title>
		<meta charset="UTF-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<meta name="apple-mobile-web-app-capable" content="yes" />
		<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
	</head>
	<body>
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
		<script src="https://cdn.auth0.com/w2/auth0-widget-5.1.min.js"></script>
		
		<script type="text/javascript">
			function getParameterByName (name) {
				name = name.replace(/[\[]/, "\\\[").replace(/[\]]/, "\\\]");
				var regexS = "[\\?&]" + name + "=([^&#]*)";
				var regex = new RegExp(regexS);
				var results = regex.exec(window.location.search);
				if (results == null) return "";
				else return decodeURIComponent(results[1].replace(/\+/g, " "));
			}
			
			if (!window.location.origin) {
				window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
			}
     	
			var allowWindowsAuth = true;
			var auth0 = new Auth0Widget({
				domain:       'YOUR_AUTH0_DOMAIN',
				clientID:     'YOUR_CLIENT_ID',
				callbackURL:  location.origin + '/_trust/'
			});
		
			window.onload = function () {
				auth0.show({
					state: 		getParameterByName('Source'),
					protocol: 	'wsfed',
					standalone: true
				}).on('signin_ready', function() {
					if (!allowWindowsAuth) return;
					if ($('#a0-widget .a0-onestep .a0-notloggedin .a0-iconlist .a0-zocial.a0-block.a0-windows.windows-auth').length > 0) return;
					var link = $('<a class="a0-zocial a0-block a0-windows windows-auth" href="/_windows/default.aspx?ReturnUrl=' + getParameterByName('ReturnUrl') + '&Source=' + getParameterByName('Source') + '"><span>Sign In with Windows Auth</span></a>');
					link.appendTo('#a0-widget .a0-onestep .a0-notloggedin .a0-iconlist');
					$('#a0-widget .a0-signin .a0-notloggedin .a0-separator').clone().show().insertBefore(link);
					$('#a0-widget #a0-onestep').css('height', 'auto');
					
					$('#a0-widget .a0-signin .a0-notloggedin .a0-iconlist').removeClass('a0-hide');
					$('#a0-widget .a0-signin .a0-notloggedin .a0-collapse-social > .a0-separator').removeClass('a0-hide');
				});
			}
	</script>
  </body>
</html>
