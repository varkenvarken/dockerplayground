$(document).ready(function() {

    var columnDefs = [
        {
        data: "id",
        title: "Id",
        type: "readonly"
        },
        {
        data: "author",
        title: "Author"
        },
        {
        data: "title",
        title: "Title"
        },
        {
        data: "isbn",
        title: "ISBN"
        }
    ];

    var myTable;

    var restendpoint = 'http://lvh.me:5555/books';

    myTable = $('#example').DataTable({
        "sPaginationType": "full_numbers",
        ajax: {
            url : restendpoint,
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
                url: restendpoint,
                type: 'POST',
                data: JSON.stringify(rowdata),
                contentType: "application/json",
                success: function(data, status, xhr){ return success(data.data, status, xhr)},
                error: error
            });
        },
        onDeleteRow: function(datatable, rowdata, success, error) {
            $.ajax({
                url: restendpoint+"/"+rowdata.id,
                type: 'DELETE',
                data: JSON.stringify(rowdata),
                contentType: "application/json",
                success: function(data, status, xhr){ return success(data.data, status, xhr)},
                error: error
            });
        },
        onEditRow: function(datatable, rowdata, success, error) {
            $.ajax({
                url: restendpoint+"/"+rowdata.id,
                type: 'PUT',
                data: JSON.stringify(rowdata),
                contentType: "application/json",
                success: function(data, status, xhr){ return success(data.data, status, xhr)},
                error: error
            });
        }
    });


});

