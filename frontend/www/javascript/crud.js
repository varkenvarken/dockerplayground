$(document).ready(function() {

    
    $.ajaxSetup({
        xhrFields: {
            withCredentials: true
        }
    });

    // link to same server on a different port
    var restendpointbooks = '/objects/books';
    var restendpointimages = '/objects/images';
    var loginpage = '/books/login.html';
    var logoutendpoint = '/auth/logout';

    var columnDefs = [
        {
        data: "id",
        title: "Id",
        readonly:true, disabled:true, visible:false
        },
        {
        data: "owner",
        title: "Owner",
        readonly:true, disabled:true, visible:false
        },
        {
        data: "author",
        title: "Author", width:"20%"
        },
        {
        data: "title",
        title: "Title", width:"30%"
        },
        {
        data: "isbn",
        title: "ISBN", pattern:"(\\d{10})|(\\d{13})"
        },
        {
        data: "publisher",
        title: "Publisher"
        },
        {
        data: "published",
        title: "Published", datepicker: { timepicker: false, dateFormat : "yy-mm-dd", changeYear: true, changeMonth: true}
        },
        {
        data: "value",
        title: "Value"
        },
        {
        data: "created",
        title: "Created", disabled:true, visible:false
        },
        {
        data: "coverart",
        title: "Cover",
        render: function (data, type, row, meta) {
                    if(data == "") { return data; }
                    return "<img class=\"coverart\" src=\""+restendpointimages+"/"+data+"?raw\">";
                }
        },
        {
        data: "isamended",
        title: "Amended", disabled:true, visible:false
        },
        {
        data: "amended",
        title: "Date", disabled:true, visible:false
        },
        {
        data: "isedited",
        title: "Edited", disabled:true, visible:false
        },
        {
        data: "edited",
        title: "Date", disabled:true, visible:false
        }
    ];

    var myTable;


    function validate_datetime(v){
        var dt = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/;
        if(v == "" || !dt.test(v)) { return new Date().toISOString().replace(/\.\d{3}/,""); }
        return v;
    }

    function validate_date(v){ // allows for an empty date
        var dt = /\d{4}-\d{2}-\d{2}/;
        if(v == "" ){ return null; }
        if(!dt.test(v)) { return new Date().toISOString().replace(/T.*/,""); }
        return v;
    }
    
    function validate(rowdata){
        
        // force dates into format falcon_autocrud imposes
        rowdata.published = validate_date(rowdata.published);
        rowdata.created = validate_datetime(rowdata.created);
        rowdata.amended = validate_datetime(rowdata.amended);
        rowdata.edited = validate_datetime(rowdata.edited);

        rowdata.isamended = Boolean(rowdata.isamended);
        rowdata.isedited = Boolean(rowdata.isedited);
        rowdata.value = Number(rowdata.value);

        console.log(rowdata);
        
        return rowdata;
    }
    
    myTable = $('#example').DataTable({
        "sPaginationType": "full_numbers",
        ajax: {
            url : restendpointbooks,
            dataSrc : 'data',
            cache: true
        },
        columns: columnDefs,
        dom: 'Bfrtip',        // Needs button container
        select: 'single',
        responsive: true,
        altEditor: true,     // Enable altEditor
        buttons: [
            {
                text: 'Add',
                name: 'add'        // do not change name
            },
            {
                extend: 'selected', // Bind to Selected row
                text: 'Edit',
                name: 'edit'        // do not change name
            },
            {
                extend: 'selected', // Bind to Selected row
                text: 'Delete',
                name: 'delete'      // do not change name
            },
            {
                text: 'Refresh',
                name: 'refresh'      // do not change name
            }
        ],
        onAddRow: function(datatable, rowdata, success, error) {
            delete rowdata.id;
            $.ajax({
                url: restendpointbooks,
                type: 'POST',
                data: JSON.stringify(validate(rowdata)),
                contentType: "application/json",
                success: function(data, status, xhr){ return success(data.data, status, xhr)},
                error: error
            });
        },
        onDeleteRow: function(datatable, rowdata, success, error) {
            $.ajax({
                url: restendpointbooks+"/"+rowdata.id,
                type: 'DELETE',
                data: JSON.stringify(rowdata),
                contentType: "application/json",
                success: function(data, status, xhr){ return success(data.data, status, xhr)},
                error: error
            });
        },
        onEditRow: function(datatable, rowdata, success, error) {
            rowdata.isedited = true;
            rowdata.edited = new Date().toISOString().replace(/\.\d{3}/,"");
            $.ajax({
                url: restendpointbooks+"/"+rowdata.id,
                type: 'PUT',
                data: JSON.stringify(validate(rowdata)),
                contentType: "application/json",
                success: function(data, status, xhr){ return success(data.data, status, xhr)},
                error: error
            });
        }
    });

    // we want to redirect, not click. See: https://stackoverflow.com/questions/503093/how-do-i-redirect-to-another-webpage
    $('#logout').click(
        function(){
            $.post(logoutendpoint,function( data ) { window.location.replace(loginpage);})
        }
    );
});

