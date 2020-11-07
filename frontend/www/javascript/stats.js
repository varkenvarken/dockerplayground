$(document).ready(function() {

    
    $.ajaxSetup({
        xhrFields: {
            withCredentials: true
        }
    });

    var endpointusers = '/auth/stats?users';

    var columnDefsUsers = [
        {
        data: "id",
        title: "Id",
        readonly:true
        },
        {
        data: "email",
        title: "Email",
        readonly:true
        },
        {
        data: "name",
        title: "Name",
        readonly:true
        },
        {
        data: "superuser",
        title: "Superuser",
        readonly:true
        },
        {
        data: "created",
        title: "Created",
        readonly:true
        },
        {
        data: "active",
        title: "Active",
        readonly:true
        },
        {
        data: "attempts",
        title: "Attempts",
        readonly:true
        },
        {
        data: "accessed",
        title: "Accessed",
        readonly:true
        },
        {
        data: "locked",
        title: "Locked",
        readonly:true
        }
    ];

    var myTable = $('#users').DataTable({
        "sPaginationType": "full_numbers",
        ajax: {
            type: "POST",
            url : endpointusers,
            dataSrc : 'data',
            cache: true
        },
        columns: columnDefsUsers,
        dom: 'Bfrtip',        // Needs button container
        select: 'single',
        responsive: true,
    });

    // we want to redirect, not click. See: https://stackoverflow.com/questions/503093/how-do-i-redirect-to-another-webpage
    $('#logout').click(
        function(){
            $.post(logoutendpoint,function( data ) { window.location.replace(loginpage);})
        }
    );
});

