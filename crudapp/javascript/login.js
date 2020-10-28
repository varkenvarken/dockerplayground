    
$(document).ready(function() {

    // https://jqueryvalidation.org/
    // at least 1 char out of each of the character classes and >= 8 long
	$.validator.addMethod("complex", function(value) {
        var anUpperCase = /[A-Z]/;
        var aLowerCase = /[a-z]/; 
        var aNumber = /[0-9]/;
        var aSpecial = /[!|@#$%^&*()-_.,<>?/\{}]/;

        if(value.length < 8){ return false; }

        var numUpper = 0;
        var numLower = 0;
        var numNums = 0;
        var numSpecials = 0;
        for(var i=0; i<value.length; i++){
            if(anUpperCase.test(value[i]))
                numUpper++;
            else if(aLowerCase.test(value[i]))
                numLower++;
            else if(aNumber.test(value[i]))
                numNums++;
            else if(aSpecial.test(value[i]))
                numSpecials++;
        }

        if(numUpper < 1 || numLower < 1 || numNums < 1 || numSpecials < 1){ return false; }
        
        return true;
	}, '<i class="fas fa-exclamation-triangle"></i> Password not complex enough');

    
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
        $("#loginerror").html("<p class='login-error'>Login failed</p>");
    }
    if(getQueryVariable("inuse")){
        $("#registrationerror").html("<p class='login-error'>Email address already registered</p>");
    }
    if(getQueryVariable("pending")){
        $("#registrationerror").html("<p class='login-info'>Confirmation email sent. Please check your inbox</p>");
    }
    if(getQueryVariable("await")){
        $("#registrationerror").html("<p class='login-info'>Confirmation email sent again. Please check your inbox</p>");
    }
    if(getQueryVariable("confirmed")){
        $("#loginerror").html("<p class='login-info'>Confirmation successful. Please log in</p>");
    }
    if(getQueryVariable("expired")){
        $("#registrationerror").html("<p class='login-error'>Confirmation link expired. Please register to access the site</p>");
    }
    
    $("#register").validate({
        rules: {
            name: {
                required: true,
                minlength: 2
            },
            password1: {
                required: true,
                complex: true
            },
            password2: {
                required: true,
                complex: true,
                equalTo: "#password1"
            },
            email: {
                required: true,
                email: true
            }
        },
        messages: {
            name: {
                required: '<i class="fas fa-exclamation-triangle"></i> Please enter a name',
                minlength: '<i class="fas fa-exclamation-triangle"></i> Your name must consist of at least 2 characters'
            },
            password: {
                required: '<i class="fas fa-exclamation-triangle"></i> Please provide a password',
            },
            password2: {
                required: '<i class="fas fa-exclamation-triangle"></i> Please provide a password',
                equalTo: '<i class="fas fa-exclamation-triangle"></i> Please enter the same password as above'
            },
            email: '<i class="fas fa-exclamation-triangle"></i> Please enter a valid email address'
        }
    });
        
    $(".loginform").validate({
        errorLabelContainer: "#loginerror",
        errorElement: "div",
        rules: {
            password: {
                required: true,
                complex: true
            },
            email: {
                required: true,
                email: true
            }
        },
        messages: {
            password: {
                required: '<i class="fas fa-exclamation-triangle"></i> Please provide a password',
            },
            email: '<i class="fas fa-exclamation-triangle"></i> Please enter a valid email address'
        }
    });

    $("form.forgottenpassword").hide();

    // todo add email verification to forgottenpassword form
    $("#forgotbutton").click(function(){
        $("form.loginform").toggle();
        $("form.forgottenpassword").toggle();
    });
    
    // todo add password complexity check to choosepassword form
    var choosepw = getQueryVariable("choosepassword");
    $('input[name="resetid"]').val(choosepw);
    if(choosepw){
        $("#register").hide();
    }else{
        $("#newpassword").hide();
    };
});

