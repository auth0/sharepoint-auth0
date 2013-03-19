<!DOCTYPE html>
<html lang="en">
  <head>
    <title>SharePoint Login</title>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="apple-mobile-web-app-capable" content="yes" />
  </head>
  <body> 
  <script type="text/javascript">
    function getParameterByName(name)
    {
      name = name.replace(/[\[]/, "\\\[").replace(/[\]]/, "\\\]");
      var regexS = "[\\?&]" + name + "=([^&#]*)";
      var regex = new RegExp(regexS);
      var results = regex.exec(window.location.search);
      if(results == null)
        return "";
      else
        return decodeURIComponent(results[1].replace(/\+/g, " "));
    }
    (function() {
      var a0 = document.createElement('script'); a0.type = 'text/javascript';
      a0.src = 'https://sdk.auth0.com/auth0.js#client=REPLACE_WITH_CLIENT_ID&protocol=wsfed&state=' + getParameterByName('Source');
      var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(a0, s);
    })();
  </script>
  <script type="text/javascript">
   window.onload = function () {
      window.Auth0.ready(function() {
        window.Auth0.signIn({ onestep: true });
      }); 
    }
  </script>
  </body>
</html>