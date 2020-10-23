$(document).ready(function() {

    
    function getQueryVariable(variable)
    {
           var query = window.location.search.substring(1);
           var vars = query.split("&");
           for (var i=0;i<vars.length;i++) {
                   var pair = vars[i].split("=");
                   if(pair[0] == variable){
                       if(pair[1] == undefined) return true;
                       return pair[1];
                       
                   }
           }
           return(false);
    }

    if(getQueryVariable("failed")){
        $("#banner").html("<p class='login-error'>Login failed</p>");
    }
    if(getQueryVariable("inuse")){
        $("#banner").html("<p class='login-error'>Email address already registered</p>");
    }
    if(getQueryVariable("pending")){
        $("#banner").html("<p class='login-info'>Confirmation email sent. Please check your inbox</p>");
    }
    if(getQueryVariable("await")){
        $("#banner").html("<p class='login-info'>Confirmation email sent again. Please check your inbox</p>");
    }
    if(getQueryVariable("confirmed")){
        $("#banner").html("<p class='login-info'>Confirmation successful. Please log in</p>");
    }
    if(getQueryVariable("expired")){
        $("#banner").html("<p class='login-error'>Confirmation link expired. Please register to access the site</p>");
    }
});

