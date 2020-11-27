$(document).ready(function() {

    function timestamp( data, type, row ) {
        // return the timestamp in local timezone, but always as yyyy-mm-dd hh:mm:ss
        // data should be a timestring in iso format in UTC without the trailing Z)
        var date = new Date(data+'Z')
        var dd = date.getDate().toString().padStart(2,'0');
        var mm = (date.getMonth()+1).toString().padStart(2,'0');
        var yy = date.getFullYear().toString().padStart(4,'0');
        var h  = date.getHours().toString().padStart(2,'0');
        var m  = date.getMinutes().toString().padStart(2,'0');
        var s  = date.getSeconds().toString().padStart(2,'0');
        return yy+"-"+mm+"-"+dd+" "+h+":"+m+":"+s;
    }

    $.ajaxSetup({
        xhrFields: {
            withCredentials: true
        }
    });

    var endpointusers = '/auth/stats/users';
    var endpointsessions = '/auth/stats/sessions';
    var endpointpendingusers = '/auth/stats/pendingusers';
    var endpointpasswordresets = '/auth/stats/passwordresets';

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
        render: timestamp,
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
        render: timestamp,
        readonly:true
        },
        {
        data: "locked",
        title: "Locked",
        render: timestamp,
        readonly:true
        }
    ];

    var columnDefsSessions = [
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
        data: "created",
        title: "Created",
        render: timestamp,
        readonly:true
        },
        {
        data: "softlimit",
        title: "Soft limit",
        render: timestamp,
        readonly:true
        },
        {
        data: "hardlimit",
        title: "Hard limit",
        render: timestamp,
        readonly:true
        }
    ];

    var columnDefsPendingusers = [
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
        data: "created",
        title: "Created",
        render: timestamp,
        readonly:true
        },
        {
        data: "expires",
        title: "Expires",
        render: timestamp,
        readonly:true
        }
    ];

    var columnDefsPasswordresets = [
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
        data: "created",
        title: "Created",
        render: timestamp,
        readonly:true
        },
        {
        data: "expires",
        title: "Expires",
        render: timestamp,
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
        dom: 'Bfrtip',        // show all control + Buttons extension
        responsive: true,
    });

    var myTable = $('#sessions').DataTable({
        "sPaginationType": "full_numbers",
        ajax: {
            type: "POST",
            url : endpointsessions,
            dataSrc : 'data',
            cache: true
        },
        columns: columnDefsSessions,
        dom: 'Bfrtip',        // show all control + Buttons extension
        select: 'single',
        responsive: true,
    });

    var myTable = $('#pendingusers').DataTable({
        "sPaginationType": "full_numbers",
        ajax: {
            type: "POST",
            url : endpointpendingusers,
            dataSrc : 'data',
            cache: true
        },
        columns: columnDefsPendingusers,
        dom: 'Bfrtip',        // show all control + Buttons extension
        select: 'single',
        responsive: true,
    });

    var myTable = $('#passwordresets').DataTable({
        "sPaginationType": "full_numbers",
        ajax: {
            type: "POST",
            url : endpointpasswordresets,
            dataSrc : 'data',
            cache: true
        },
        columns: columnDefsPasswordresets,
        dom: 'Bfrtip',        // show all control + Buttons extension
        select: 'single',
        responsive: true,
    });

    // we want to redirect, not click. See: https://stackoverflow.com/questions/503093/how-do-i-redirect-to-another-webpage
    $('#logout').click(
        function(){
            $.post(logoutendpoint,function( data ) { window.location.replace(loginpage);})
        }
    );

    $(function() {
        $("#tabs").tabs();
    });

    $(".tab").click(function(){
        console.log("click" + $(this).data("table"));
        var tableId = $(this).data("table");
        $("#"+tableId).DataTable().ajax.reload().columns.adjust().draw();
    });

});

